"""Write the documented HKLM removable-storage values.

Nothing in this module accepts an arbitrary registry path. ``assert_policy_value``
rejects every name other than the five values the planner emits, and the USBSTOR
service key is opened, never created.
"""

from __future__ import annotations

import sys

from usbac_py.exceptions import PlatformError, PolicyApplyError
from usbac_py.planner import (
    USBSTOR_KEY,
    PlannedRegistryValue,
    RegistryEditor,
    apply_plan,
    assert_policy_value,
)


def _require_windows() -> None:
    if sys.platform != "win32":
        raise PlatformError("레지스트리 정책은 Windows에서만 적용할 수 있습니다.")


class WinregEditor(RegistryEditor):
    def key_exists(self, key_path: str) -> bool:
        _require_windows()
        import winreg

        try:
            handle = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            )
        except FileNotFoundError:
            return False
        except PermissionError as exc:
            raise PlatformError("HKLM을 읽으려면 관리자 권한으로 다시 실행하세요.") from exc
        else:
            winreg.CloseKey(handle)
            return True

    def set_dword(self, key_path: str, value_name: str, value: int) -> None:
        _require_windows()
        assert_policy_value(PlannedRegistryValue(key_path, value_name, int(value)))
        import winreg

        access = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        try:
            if key_path.lower() == USBSTOR_KEY.lower():
                handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, access)
            else:
                handle = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, access)
        except FileNotFoundError as exc:
            raise PolicyApplyError(
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR 키가 없습니다. "
                "레지스트리를 변경하지 않았습니다."
            ) from exc
        except PermissionError as exc:
            raise PlatformError("HKLM을 쓰려면 관리자 권한으로 다시 실행하세요.") from exc
        try:
            winreg.SetValueEx(handle, value_name, 0, winreg.REG_DWORD, int(value))
        finally:
            winreg.CloseKey(handle)


class WinregReader:
    def try_get_dword(self, key_path: str, value_name: str) -> int | None:
        if sys.platform != "win32":
            return None
        import winreg

        try:
            handle = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                key_path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            )
            try:
                raw, kind = winreg.QueryValueEx(handle, value_name)
            finally:
                winreg.CloseKey(handle)
        except OSError:
            return None
        if kind != winreg.REG_DWORD or isinstance(raw, bool) or not isinstance(raw, int):
            return None
        return int(raw)


class RegistryPolicyEnforcer:
    def __init__(self, editor: WinregEditor | None = None) -> None:
        self._editor = editor or WinregEditor()

    def apply(self, plan) -> None:
        _require_windows()
        apply_plan(plan, self._editor)
