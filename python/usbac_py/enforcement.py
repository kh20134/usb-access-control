"""Decide which USBSTOR device nodes to enable or disable.

Only instances whose ID starts with USBSTOR\\ are considered. Keyboards, mice,
and other USB devices are ignored even if a caller passes them in.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from usbac_py.identity import is_usbstor_instance
from usbac_py.matcher import find_match
from usbac_py.models import EffectiveAccess, UsbStorageDevice, WhitelistEntry
from usbac_py.planner import EnforcementPlan, enforceable_access


class ObservationKind(Enum):
    PRESENT_AT_START = "presentAtStart"
    INSERTED = "inserted"
    REMOVED = "removed"


@dataclass(frozen=True)
class DeviceObservation:
    kind: ObservationKind
    device: UsbStorageDevice


@dataclass(frozen=True)
class DeviceControlAction:
    instance_id: str
    device: UsbStorageDevice | None
    enable: bool | None
    access: EffectiveAccess
    match: WhitelistEntry | None
    reason: str


class DeviceWatch:
    def __init__(self) -> None:
        self._present: dict[str, UsbStorageDevice] = {}
        self._has_baseline = False

    def reset(self) -> None:
        self._present.clear()
        self._has_baseline = False

    def observe(
        self,
        observed: list[UsbStorageDevice],
        suppressed_removals: list[str] | None = None,
    ) -> list[DeviceObservation]:
        current = index_storage_devices(observed)
        if self._has_baseline and suppressed_removals:
            for instance_id in suppressed_removals:
                key = instance_id.strip()
                if key.lower() not in {item.lower() for item in current} and _lookup(self._present, key) is not None:
                    hidden = _lookup(self._present, key)
                    if hidden is not None:
                        current[hidden.instance_id] = hidden
        events: list[DeviceObservation] = []
        if not self._has_baseline:
            self._has_baseline = True
            events.extend(
                DeviceObservation(ObservationKind.PRESENT_AT_START, device) for device in current.values()
            )
        else:
            for device in current.values():
                if _lookup(self._present, device.instance_id) is None:
                    events.append(DeviceObservation(ObservationKind.INSERTED, device))
            for previous in self._present.values():
                if _lookup(current, previous.instance_id) is None:
                    events.append(DeviceObservation(ObservationKind.REMOVED, previous))
        self._present = current
        return events


def index_storage_devices(observed: list[UsbStorageDevice]) -> dict[str, UsbStorageDevice]:
    indexed: dict[str, UsbStorageDevice] = {}
    for device in observed:
        if not device.is_mass_storage or not is_usbstor_instance(device.instance_id):
            continue
        indexed[device.instance_id.strip()] = device
    return indexed


def decide_actions(
    plan: EnforcementPlan,
    whitelist: list[WhitelistEntry],
    present: list[UsbStorageDevice],
    previously_disabled: list[str],
) -> list[DeviceControlAction]:
    actions: list[DeviceControlAction] = []
    disabled = {item.strip() for item in previously_disabled if is_usbstor_instance(item)}
    present_ids: set[str] = set()
    for device in index_storage_devices(present).values():
        present_ids.add(device.instance_id.lower())
        match = find_match(whitelist, device)
        access = enforceable_access(plan, match is not None)
        if plan.selective_device_control:
            if access is EffectiveAccess.BLOCK:
                actions.append(
                    DeviceControlAction(
                        device.instance_id,
                        device,
                        False,
                        access,
                        match,
                        "화이트리스트와 일치하지 않아 USBSTOR 장치 노드를 비활성화합니다.",
                    )
                )
            elif _contains(disabled, device.instance_id):
                actions.append(
                    DeviceControlAction(
                        device.instance_id,
                        device,
                        True,
                        access,
                        match,
                        "승인된 장치이므로 이전에 끈 USBSTOR 장치 노드를 다시 켭니다.",
                    )
                )
            else:
                actions.append(
                    DeviceControlAction(
                        device.instance_id,
                        device,
                        None,
                        access,
                        match,
                        "장치 노드를 바꾸지 않습니다."
                        if match is None
                        else f"화이트리스트 '{match.display_name}'과 일치합니다. 장치 노드를 유지합니다.",
                    )
                )
        elif _contains(disabled, device.instance_id):
            actions.append(
                DeviceControlAction(
                    device.instance_id,
                    device,
                    True,
                    access,
                    match,
                    "선택적 차단이 아니므로 이전에 끈 USBSTOR 장치 노드를 다시 켭니다.",
                )
            )
        else:
            actions.append(
                DeviceControlAction(
                    device.instance_id,
                    device,
                    None,
                    access,
                    match,
                    _describe_passive(plan, access, match),
                )
            )
    if not plan.selective_device_control:
        for instance_id in sorted(disabled, key=str.lower):
            if instance_id.lower() in present_ids:
                continue
            actions.append(
                DeviceControlAction(
                    instance_id,
                    None,
                    True,
                    EffectiveAccess.ALLOW,
                    None,
                    "이전에 끈 장치가 현재 목록에 없어도, 선택적 차단을 해제했으므로 다시 켜기를 시도합니다.",
                )
            )
    return actions


def _describe_passive(
    plan: EnforcementPlan,
    access: EffectiveAccess,
    match: WhitelistEntry | None,
) -> str:
    if plan.whitelist_write_exemption_unsupported and match is not None:
        return f"화이트리스트 '{match.display_name}'과 일치하지만, 읽기 전용은 전역 정책이라 쓰기는 허용되지 않습니다."
    if access is EffectiveAccess.ALLOW:
        return "기본 정책에 따라 허용됩니다. 장치 노드를 바꾸지 않습니다."
    if access is EffectiveAccess.READ_ONLY:
        return "기본 정책에 따라 읽기 전용입니다. 장치 노드를 바꾸지 않습니다."
    return "기본 정책에 따라 차단됩니다. 전역 레지스트리 정책을 사용하며 장치 노드를 개별적으로 끄지 않습니다."


def _lookup(mapping: dict[str, UsbStorageDevice], instance_id: str) -> UsbStorageDevice | None:
    for key, device in mapping.items():
        if key.lower() == instance_id.lower():
            return device
    return None


def _contains(values: set[str], instance_id: str) -> bool:
    return any(item.lower() == instance_id.lower() for item in values)
