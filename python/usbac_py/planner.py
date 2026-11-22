"""Decide which documented Windows policy values a mode requires.

The planner does not write to the registry. Callers that apply a plan must
already be running elevated on Windows. Read-only is machine-wide: a whitelist
entry does not grant write access, because these registry values have no
per-device write exception.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from usbac_py.exceptions import PolicyApplyError
from usbac_py.models import EffectiveAccess, PolicyMode

USBSTOR_KEY = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
USBSTOR_START = "Start"
USBSTOR_DEMAND_START = 3
USBSTOR_DISABLED = 4

WRITE_PROTECT_KEY = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
WRITE_PROTECT_VALUE = "WriteProtect"

REMOVABLE_KEY = r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
DENY_ALL = "Deny_All"
REMOVABLE_DISK_GUID = "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
DENY_READ = "Deny_Read"
DENY_WRITE = "Deny_Write"


def removable_disk_key() -> str:
    return REMOVABLE_KEY + "\\" + REMOVABLE_DISK_GUID


@dataclass(frozen=True)
class PlannedRegistryValue:
    key_path: str
    value_name: str
    dword: int


@dataclass(frozen=True)
class EnforcementPlan:
    mode: PolicyMode
    whitelist_present: bool
    usbstor_start: int
    write_protect: bool
    deny_all: bool
    deny_read: bool
    deny_write: bool
    selective_device_control: bool
    whitelist_write_exemption_unsupported: bool
    notes: tuple[str, ...]

    def registry_values(self) -> tuple[PlannedRegistryValue, ...]:
        if self.usbstor_start not in (USBSTOR_DEMAND_START, USBSTOR_DISABLED):
            raise PolicyApplyError("USBSTOR Start 값은 3(수동 시작) 또는 4(사용 안 함)만 쓸 수 있습니다.")
        values = (
            PlannedRegistryValue(USBSTOR_KEY, USBSTOR_START, self.usbstor_start),
            PlannedRegistryValue(WRITE_PROTECT_KEY, WRITE_PROTECT_VALUE, 1 if self.write_protect else 0),
            PlannedRegistryValue(REMOVABLE_KEY, DENY_ALL, 1 if self.deny_all else 0),
            PlannedRegistryValue(removable_disk_key(), DENY_READ, 1 if self.deny_read else 0),
            PlannedRegistryValue(removable_disk_key(), DENY_WRITE, 1 if self.deny_write else 0),
        )
        for value in values:
            assert_policy_value(value)
        return values


class RegistryEditor(Protocol):
    def key_exists(self, key_path: str) -> bool: ...

    def set_dword(self, key_path: str, value_name: str, value: int) -> None: ...


class RegistryReader(Protocol):
    def try_get_dword(self, key_path: str, value_name: str) -> int | None: ...


@dataclass(frozen=True)
class RegistryObservation:
    key_path: str
    value_name: str
    actual: int | None
    expected: int
    matches: bool


def intended_access(mode: PolicyMode, whitelisted: bool) -> EffectiveAccess:
    if whitelisted:
        return EffectiveAccess.ALLOW
    if mode is PolicyMode.ALLOW:
        return EffectiveAccess.ALLOW
    if mode is PolicyMode.READ_ONLY:
        return EffectiveAccess.READ_ONLY
    return EffectiveAccess.BLOCK


def enforceable_access(plan: EnforcementPlan, whitelisted: bool) -> EffectiveAccess:
    if plan.selective_device_control:
        return EffectiveAccess.ALLOW if whitelisted else EffectiveAccess.BLOCK
    if plan.whitelist_write_exemption_unsupported and whitelisted and plan.mode is PolicyMode.READ_ONLY:
        return EffectiveAccess.READ_ONLY
    return intended_access(plan.mode, whitelisted)


def create_plan(mode: PolicyMode, has_whitelist: bool) -> EnforcementPlan:
    if mode is PolicyMode.ALLOW:
        return _allow(has_whitelist)
    if mode is PolicyMode.READ_ONLY:
        return _read_only(has_whitelist)
    if mode is PolicyMode.BLOCK and not has_whitelist:
        return _block_all()
    if mode is PolicyMode.BLOCK:
        return _block_except_whitelist()
    return _block_all()


def assert_policy_value(value: PlannedRegistryValue) -> None:
    """Reject any registry write that is not one of the five documented policy values."""
    key = value.key_path
    name = value.value_name
    dword = value.dword
    allowed = (
        (key, name) == (USBSTOR_KEY, USBSTOR_START) and dword in (USBSTOR_DEMAND_START, USBSTOR_DISABLED),
        (key, name) == (WRITE_PROTECT_KEY, WRITE_PROTECT_VALUE) and dword in (0, 1),
        (key, name) == (REMOVABLE_KEY, DENY_ALL) and dword in (0, 1),
        (key, name) == (removable_disk_key(), DENY_READ) and dword in (0, 1),
        (key, name) == (removable_disk_key(), DENY_WRITE) and dword in (0, 1),
    )
    if not any(allowed):
        raise PolicyApplyError(
            "정책 적용은 USBSTOR Start, WriteProtect, Deny_All, 이동식 디스크 Deny_Read/Deny_Write 만 바꿉니다."
        )


def apply_plan(plan: EnforcementPlan, editor: RegistryEditor) -> None:
    values = plan.registry_values()
    if any(value.key_path.lower() == USBSTOR_KEY.lower() for value in values) and not editor.key_exists(USBSTOR_KEY):
        raise PolicyApplyError(
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR 키가 없습니다. "
            "USB 저장 드라이버 구성이 예상과 달라 레지스트리를 변경하지 않았습니다."
        )
    for value in values:
        editor.set_dword(value.key_path, value.value_name, value.dword)


def compare_registry(plan: EnforcementPlan, reader: RegistryReader) -> tuple[RegistryObservation, ...]:
    observations: list[RegistryObservation] = []
    for value in plan.registry_values():
        actual = reader.try_get_dword(value.key_path, value.value_name)
        observations.append(
            RegistryObservation(
                key_path=value.key_path,
                value_name=value.value_name,
                actual=actual,
                expected=value.dword,
                matches=actual == value.dword,
            )
        )
    return tuple(observations)


def status_text(mode: PolicyMode, plan: EnforcementPlan, whitelist_count: int, applied: bool) -> str:
    applied_text = "이 PC에 적용됨" if applied else "아직 이 PC에 적용되지 않음"
    if plan.selective_device_control:
        scope = "승인된 USB만 허용"
    elif plan.whitelist_write_exemption_unsupported:
        scope = "읽기 전용은 전역 정책이라 화이트리스트도 쓸 수 없음"
    elif mode is PolicyMode.ALLOW and whitelist_count > 0:
        scope = "기본 정책이 허용이라 화이트리스트는 예외가 아님"
    else:
        scope = "모든 USB 저장장치에 기본 정책 적용"
    return f"{mode.korean} · {scope} · {applied_text}"


def _allow(has_whitelist: bool) -> EnforcementPlan:
    note = (
        "기본 정책이 허용이므로 화이트리스트는 접근을 더 제한하지 않습니다. 승인된 장치만 쓰려면 기본 정책을 차단으로 두세요."
        if has_whitelist
        else "USB 대용량 저장장치 읽기와 쓰기를 막지 않습니다."
    )
    return EnforcementPlan(
        mode=PolicyMode.ALLOW,
        whitelist_present=has_whitelist,
        usbstor_start=USBSTOR_DEMAND_START,
        write_protect=False,
        deny_all=False,
        deny_read=False,
        deny_write=False,
        selective_device_control=False,
        whitelist_write_exemption_unsupported=False,
        notes=(
            "USBSTOR 서비스를 수동 시작(3)으로 두고, 이동식 저장장치 거부 값과 WriteProtect를 0으로 둡니다.",
            note,
        ),
    )


def _read_only(has_whitelist: bool) -> EnforcementPlan:
    if has_whitelist:
        notes = (
            "이동식 디스크 클래스에 Deny_Write=1, Deny_Read=0을 쓰고 StorageDevicePolicies\\WriteProtect=1을 켭니다.",
            "이 쓰기 금지는 PC 전역입니다. 필터 드라이버가 없으므로 화이트리스트 장치만 쓰기를 허용할 수 없습니다.",
            "Deny_All은 켜지 않습니다. Deny_All은 읽기까지 막으며 개별 설정보다 우선합니다.",
            "WriteProtect는 UASP 장치와 MTP(휴대폰)에 적용되지 않을 수 있습니다. 그룹 정책 쓰기 거부가 기본 수단입니다.",
        )
    else:
        notes = (
            "이동식 디스크는 읽을 수 있고 쓰기는 거부됩니다.",
            "StorageDevicePolicies\\WriteProtect는 보조 수단입니다. UASP 장치에는 적용되지 않을 수 있습니다.",
            "이미 마운트된 볼륨은 다시 연결하거나 다시 로그온해야 정책이 반영될 수 있습니다.",
        )
    return EnforcementPlan(
        mode=PolicyMode.READ_ONLY,
        whitelist_present=has_whitelist,
        usbstor_start=USBSTOR_DEMAND_START,
        write_protect=True,
        deny_all=False,
        deny_read=False,
        deny_write=True,
        selective_device_control=False,
        whitelist_write_exemption_unsupported=has_whitelist,
        notes=notes,
    )


def _block_all() -> EnforcementPlan:
    return EnforcementPlan(
        mode=PolicyMode.BLOCK,
        whitelist_present=False,
        usbstor_start=USBSTOR_DISABLED,
        write_protect=False,
        deny_all=True,
        deny_read=True,
        deny_write=True,
        selective_device_control=False,
        whitelist_write_exemption_unsupported=False,
        notes=(
            "USBSTOR 서비스를 사용 안 함(4)으로 두고, 이동식 저장장치 전체 거부(Deny_All)와 이동식 디스크 읽기/쓰기 거부를 켭니다.",
            "Deny_All은 CD, SD, WPD/MTP를 포함한 이동식 저장 클래스 전체에 적용됩니다. USB 키보드와 마우스는 USBSTOR가 아니라 영향받지 않습니다.",
            "이미 연결된 볼륨은 장치를 다시 꽂거나 PC를 다시 시작하기 전까지 남아 있을 수 있습니다.",
        ),
    )


def _block_except_whitelist() -> EnforcementPlan:
    return EnforcementPlan(
        mode=PolicyMode.BLOCK,
        whitelist_present=True,
        usbstor_start=USBSTOR_DEMAND_START,
        write_protect=False,
        deny_all=False,
        deny_read=False,
        deny_write=False,
        selective_device_control=True,
        whitelist_write_exemption_unsupported=False,
        notes=(
            "승인된 장치만 허용하려면 USBSTOR와 전역 거부를 켜 두면 승인 장치까지 막힙니다. "
            "그래서 레지스트리 거부는 끄고, USBSTOR 장치 노드만 선택적으로 비활성화합니다.",
            "선택적 제어는 이 프로그램이 관리자 권한으로 감시 중일 때만 유지됩니다. 프로세스가 없으면 새로 꽂은 장치가 열릴 수 있습니다.",
            "VID/PID를 확인하지 못한 저장장치는 허용하지 않습니다.",
        ),
    )
