"""Policy session: authorization, persistence, and enforcement orchestration.

Windows registry and device-node calls are injected. Tests supply in-memory
implementations. ``control_devices`` is false unless the process is elevated,
so a normal user session can record decisions without calling cfgmgr32.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from usbac_py.audit import AuditEvent, AuditLog, write_csv
from usbac_py.enforcement import (
    DeviceControlAction,
    DeviceObservation,
    DeviceWatch,
    ObservationKind,
    decide_actions,
)
from usbac_py.exceptions import AuthorizationError, DeviceControlError, PlatformError, PolicyApplyError, ValidationError
from usbac_py.identity import is_usbstor_instance
from usbac_py.matcher import MAX_ENTRIES, create_entry, find_match, same_identity
from usbac_py.models import (
    AuditAction,
    EffectiveAccess,
    PolicyDocument,
    PolicyMode,
    UsbStorageDevice,
    WhitelistEntry,
)
from usbac_py.password import create_password, ensure_authorized
from usbac_py.planner import EnforcementPlan, RegistryReader, compare_registry, create_plan, enforceable_access
from usbac_py.store import EnforcementStateStore, PolicyStore


class PolicyEnforcer(Protocol):
    def apply(self, plan: EnforcementPlan) -> None: ...


class DeviceEnumerator(Protocol):
    def list_mass_storage_devices(self) -> list[UsbStorageDevice]: ...


class DeviceController(Protocol):
    def set_mass_storage_enabled(self, instance_id: str, enabled: bool) -> str: ...


@dataclass(frozen=True)
class UserContext:
    user_name: str
    machine_name: str


@dataclass(frozen=True)
class ApplyResult:
    plan: EnforcementPlan
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class ScanOutcome:
    devices: tuple[UsbStorageDevice, ...]
    observations: tuple[DeviceObservation, ...]
    actions: tuple[DeviceControlAction, ...]
    warnings: tuple[str, ...]
    control_results: dict[str, str]


class PolicySession:
    def __init__(
        self,
        store: PolicyStore,
        audit: AuditLog,
        state_store: EnforcementStateStore,
        user: UserContext,
        enforcer: PolicyEnforcer,
        devices: DeviceEnumerator,
        controller: DeviceController,
        *,
        elevated: bool,
        control_devices: bool,
        clock: Callable[[], datetime] | None = None,
        registry_reader: RegistryReader | None = None,
    ) -> None:
        self._store = store
        self._audit = audit
        self._state_store = state_store
        self._user = user
        self._enforcer = enforcer
        self._devices = devices
        self._controller = controller
        self.elevated = elevated
        self.control_devices = control_devices and elevated
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._registry_reader = registry_reader
        self._watch = DeviceWatch()
        self._gate = threading.RLock()
        loaded = store.load_or_create()
        self._document = loaded.document
        self.load_warnings = loaded.warnings

    @property
    def document(self) -> PolicyDocument:
        return self._document

    @property
    def user_name(self) -> str:
        return self._user.user_name

    @property
    def machine_name(self) -> str:
        return self._user.machine_name

    @property
    def data_directory(self) -> Path:
        return self._store.directory

    def preview(self) -> EnforcementPlan:
        return create_plan(self._document.mode, len(self._document.whitelist) > 0)

    def read_registry_drift(self):
        if self._registry_reader is None:
            return ()
        return compare_registry(self.preview(), self._registry_reader)

    def set_mode(self, mode: PolicyMode, password: str | None) -> None:
        with self._gate:
            self._authorize(password)
            if self._document.mode == mode:
                return
            self._document.mode = mode
            self._touch()
            self._store.save(self._document)

    def add_whitelist(
        self,
        vendor_id: str,
        product_id: str,
        serial_number: str | None,
        display_name: str,
        note: str | None,
        password: str | None,
    ) -> WhitelistEntry:
        with self._gate:
            self._authorize(password)
            if len(self._document.whitelist) >= MAX_ENTRIES:
                raise ValidationError(f"화이트리스트는 {MAX_ENTRIES}개까지 저장할 수 있습니다.")
            entry = create_entry(
                vendor_id,
                product_id,
                serial_number,
                display_name,
                note,
                self._now(),
            )
            if any(same_identity(existing, entry) for existing in self._document.whitelist):
                raise ValidationError("같은 VID, PID, 일련번호의 항목이 이미 있습니다.")
            self._document.whitelist.append(entry)
            self._touch()
            self._store.save(self._document)
            self._write_audit(
                AuditAction.WHITELIST_ADDED,
                result="성공",
                detail=f"{entry.display_name} ({entry.vendor_id}:{entry.product_id})",
                vendor_id=entry.vendor_id,
                product_id=entry.product_id,
                serial=entry.serial_number,
                device_name=entry.display_name,
            )
            return entry

    def remove_whitelist(self, entry_id, password: str | None) -> bool:
        with self._gate:
            self._authorize(password)
            match = next((item for item in self._document.whitelist if item.id == entry_id), None)
            if match is None:
                return False
            self._document.whitelist.remove(match)
            self._touch()
            self._store.save(self._document)
            self._write_audit(
                AuditAction.WHITELIST_REMOVED,
                result="성공",
                detail=match.display_name,
                vendor_id=match.vendor_id,
                product_id=match.product_id,
                serial=match.serial_number,
                device_name=match.display_name,
            )
            return True

    def set_admin_password(self, current_password: str | None, new_password: str) -> None:
        with self._gate:
            self._authorize(current_password)
            self._document.admin_password = create_password(new_password)
            self._touch()
            self._store.save(self._document)
            self._write_audit(AuditAction.PASSWORD_SET, result="성공", detail="관리자 암호를 설정했습니다.")

    def clear_admin_password(self, current_password: str | None) -> None:
        with self._gate:
            self._authorize(current_password)
            self._document.admin_password = None
            self._touch()
            self._store.save(self._document)
            self._write_audit(AuditAction.PASSWORD_CLEARED, result="성공", detail="관리자 암호를 해제했습니다.")

    def apply(self, password: str | None, *, dry_run: bool = False) -> ApplyResult:
        with self._gate:
            if dry_run:
                return ApplyResult(
                    self.preview(),
                    ("미리보기입니다. Windows 레지스트리와 장치 노드는 변경하지 않았습니다.",),
                )
            self._authorize(password)
            if not self.elevated:
                message = (
                    "정책을 Windows에 적용하려면 관리자 권한으로 다시 실행하세요. "
                    "사용자 모드에서는 정책을 저장하고 장치별 예상 접근을 계산할 수 있지만, "
                    "HKLM과 USBSTOR 장치 노드는 바꾸지 못합니다."
                )
                self._write_audit(AuditAction.POLICY_REJECTED, result="실패", detail=message)
                raise PlatformError(message)
            plan = self.preview()
            try:
                self._enforcer.apply(plan)
            except (PolicyApplyError, PlatformError, OSError, PermissionError) as exc:
                self._write_audit(AuditAction.POLICY_REJECTED, result="실패", detail=str(exc))
                raise
            scan = self._scan_locked()
            now = self._now()
            self._document.applied_fingerprint = self._document.desired_fingerprint()
            self._document.applied_at = now
            self._document.updated_at = now
            self._document.updated_by = self._user.user_name
            self._store.save(self._document)
            detail = " ".join(plan.notes)
            self._write_audit(
                AuditAction.POLICY_APPLIED,
                result="성공" if not scan.warnings else "부분 성공",
                detail=detail,
            )
            return ApplyResult(plan, scan.warnings)

    def scan_and_enforce(self) -> ScanOutcome:
        with self._gate:
            return self._scan_locked()

    def list_devices(self) -> list[UsbStorageDevice]:
        with self._gate:
            return list(self._devices.list_mass_storage_devices())

    def explain(self, device: UsbStorageDevice) -> EffectiveAccess:
        with self._gate:
            match = find_match(self._document.whitelist, device)
            return enforceable_access(self.preview(), match is not None)

    def recent_logs(self, limit: int) -> list[AuditEvent]:
        if limit < 1:
            raise ValidationError("로그 개수는 1 이상이어야 합니다.")
        return self._audit.read_all()[-limit:]

    def export_logs(self, path: Path) -> None:
        with self._gate:
            events = self._audit.read_all()
            write_csv(Path(path), events)
            self._write_audit(AuditAction.LOG_EXPORTED, result="성공", detail=str(path))

    def mark_monitor(self, started: bool) -> None:
        with self._gate:
            self._write_audit(
                AuditAction.MONITOR_STARTED if started else AuditAction.MONITOR_STOPPED,
                result="성공",
                detail="USB 저장장치 감시를 시작했습니다." if started else "USB 저장장치 감시를 중지했습니다.",
            )

    def _scan_locked(self) -> ScanOutcome:
        devices = list(self._devices.list_mass_storage_devices())
        state = self._state_store.load()
        observations = self._watch.observe(devices, state.disabled_instance_ids)
        plan = self.preview()
        actions = decide_actions(plan, self._document.whitelist, devices, state.disabled_instance_ids)
        warnings: list[str] = []
        disabled = {item for item in state.disabled_instance_ids if is_usbstor_instance(item)}
        results: dict[str, str] = {}
        reported_privilege = False
        for action in actions:
            if action.enable is None:
                results[action.instance_id] = "변경 없음"
                continue
            if not self.control_devices:
                results[action.instance_id] = "권한 없음"
                if not reported_privilege:
                    warnings.append(
                        "관리자 권한이 없어 장치 노드를 바꾸지 않았습니다. 허용, 읽기 전용, 차단 결정만 기록합니다."
                    )
                    reported_privilege = True
                continue
            try:
                outcome = self._controller.set_mass_storage_enabled(action.instance_id, action.enable)
            except DeviceControlError as exc:
                if exc.device_missing:
                    _discard(disabled, action.instance_id)
                    results[action.instance_id] = "장치 없음"
                else:
                    results[action.instance_id] = "실패"
                warnings.append(str(exc))
                continue
            except (OSError, PermissionError, PlatformError) as exc:
                results[action.instance_id] = "실패"
                warnings.append(str(exc))
                continue
            if outcome == "changed":
                if action.enable:
                    _discard(disabled, action.instance_id)
                else:
                    disabled.add(action.instance_id)
                results[action.instance_id] = "성공"
            elif outcome == "not_found":
                _discard(disabled, action.instance_id)
                results[action.instance_id] = "장치 없음"
                warnings.append(f"{action.instance_id}: 장치 노드를 찾지 못했습니다.")
            elif outcome == "skipped":
                results[action.instance_id] = "권한 없음"
                if not reported_privilege:
                    warnings.append("장치 노드를 바꾸지 않았습니다. 결정만 기록합니다.")
                    reported_privilege = True
            else:
                results[action.instance_id] = "실패"
                warnings.append(f"{action.instance_id}: 장치 노드를 바꾸지 못했습니다.")
        if self.control_devices:
            state.disabled_instance_ids = sorted(disabled, key=str.lower)
            self._state_store.save(state)
        for observation in observations:
            action = next(
                (item for item in actions if item.instance_id.lower() == observation.device.instance_id.lower()),
                None,
            )
            self._write_device_observation(observation, action, results)
        return ScanOutcome(
            devices=tuple(devices),
            observations=tuple(observations),
            actions=tuple(actions),
            warnings=tuple(warnings),
            control_results=results,
        )

    def _write_device_observation(
        self,
        observation: DeviceObservation,
        action: DeviceControlAction | None,
        results: dict[str, str],
    ) -> None:
        device = observation.device
        if observation.kind is ObservationKind.REMOVED:
            self._write_audit(
                AuditAction.DEVICE_REMOVED,
                result="기록",
                detail="장치가 분리되었습니다.",
                instance_id=device.instance_id,
                vendor_id=device.vendor_id,
                product_id=device.product_id,
                serial=device.serial_number,
                device_name=device.friendly_name,
            )
            return
        access = action.access if action is not None else self.explain(device)
        audit_action = {
            EffectiveAccess.ALLOW: AuditAction.DEVICE_ALLOWED,
            EffectiveAccess.READ_ONLY: AuditAction.DEVICE_READ_ONLY,
        }.get(access, AuditAction.DEVICE_BLOCKED)
        control = results.get(device.instance_id)
        kind = "초기 검색" if observation.kind is ObservationKind.PRESENT_AT_START else "연결"
        reason = action.reason if action is not None else ""
        if control in {"실패", "장치 없음"}:
            detail = f"{kind}. {reason} 결과: {control}."
        else:
            detail = f"{kind}. {reason}"
        self._write_audit(
            audit_action,
            result="실패" if control == "실패" else access.korean,
            detail=detail,
            instance_id=device.instance_id,
            vendor_id=device.vendor_id,
            product_id=device.product_id,
            serial=device.serial_number,
            device_name=device.friendly_name,
        )

    def _authorize(self, password: str | None) -> None:
        try:
            ensure_authorized(self._document, password)
        except AuthorizationError:
            self._write_audit(AuditAction.POLICY_REJECTED, result="거부", detail="관리자 암호가 올바르지 않습니다.")
            raise

    def _touch(self) -> None:
        self._document.updated_at = self._now()
        self._document.updated_by = self._user.user_name

    def _now(self) -> datetime:
        current = self._clock()
        if current.tzinfo is None:
            return current.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc)

    def _write_audit(
        self,
        action: AuditAction,
        *,
        result: str,
        detail: str | None,
        instance_id: str | None = None,
        vendor_id: str | None = None,
        product_id: str | None = None,
        serial: str | None = None,
        device_name: str | None = None,
    ) -> None:
        self._audit.append(
            AuditEvent(
                timestamp=self._now(),
                user_name=self._user.user_name,
                machine_name=self._user.machine_name,
                action=action,
                instance_id=instance_id,
                vendor_id=vendor_id,
                product_id=product_id,
                serial_number=serial,
                device_name=device_name,
                policy_mode=self._document.mode.korean,
                result=result,
                detail=detail,
            )
        )


def _discard(values: set[str], instance_id: str) -> None:
    found = [item for item in values if item.lower() == instance_id.lower()]
    for item in found:
        values.discard(item)
