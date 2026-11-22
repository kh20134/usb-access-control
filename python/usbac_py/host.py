"""Wire the pure session to Windows APIs, or to refusing adapters elsewhere."""

from __future__ import annotations

import getpass
import os
import platform
import sys
from pathlib import Path

from usbac_py.audit import AuditLog
from usbac_py.exceptions import PlatformError
from usbac_py.session import DeviceController, DeviceEnumerator, PolicyEnforcer, PolicySession, UserContext
from usbac_py.store import EnforcementStateStore, PolicyStore, PortableFileProtector, default_data_directory
from usbac_py.windows.acl import WindowsAclProtector, is_managed_directory
from usbac_py.windows.elevation import is_elevated


class UnavailableEnforcer:
    def apply(self, plan) -> None:
        raise PlatformError(
            "레지스트리 정책 적용은 Windows 10/11의 관리자 권한에서만 가능합니다. "
            "사용자 모드에서는 정책을 저장하고 예상 접근만 계산할 수 있습니다."
        )


class UnavailableDevices:
    def list_mass_storage_devices(self):
        raise PlatformError("USB 저장장치 열거는 Windows에서만 가능합니다.")


class ObservingController:
    def set_mass_storage_enabled(self, instance_id: str, enabled: bool) -> str:
        from usbac_py.identity import ensure_usbstor_instance

        ensure_usbstor_instance(instance_id)
        return "skipped"


def current_user() -> UserContext:
    try:
        user_name = getpass.getuser()
    except Exception:
        user_name = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    return UserContext(user_name=user_name, machine_name=platform.node())


def create_session(data_dir: str | None = None, *, observe_only: bool = False) -> PolicySession:
    directory = Path(data_dir).expanduser() if data_dir else default_data_directory()
    elevated = is_elevated()
    program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
    if elevated and is_managed_directory(directory, program_data):
        protector = WindowsAclProtector(program_data)
    else:
        protector = PortableFileProtector()
    store = PolicyStore(directory, protector)
    audit = AuditLog(directory, protector)
    state_store = EnforcementStateStore(directory, protector)
    control_devices = False
    enforcer: PolicyEnforcer
    controller: DeviceController
    devices: DeviceEnumerator
    reader = None
    if sys.platform == "win32":
        from usbac_py.windows.devnode import DevNodeController
        from usbac_py.windows.registry import RegistryPolicyEnforcer, WinregReader
        from usbac_py.windows.setupapi import SetupApiDeviceEnumerator

        devices = SetupApiDeviceEnumerator()
        reader = WinregReader()
        if elevated and not observe_only:
            enforcer = RegistryPolicyEnforcer()
            controller = DevNodeController()
            control_devices = True
        else:
            enforcer = UnavailableEnforcer()
            controller = ObservingController()
    else:
        devices = UnavailableDevices()
        enforcer = UnavailableEnforcer()
        controller = ObservingController()
    return PolicySession(
        store,
        audit,
        state_store,
        current_user(),
        enforcer,
        devices,
        controller,
        elevated=elevated,
        control_devices=control_devices,
        registry_reader=reader,
    )
