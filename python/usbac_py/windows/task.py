"""Scheduled-task command lines. The task runs as SYSTEM at startup.

SYSTEM must be able to see the Python executable. A per-user virtualenv under
AppData is a poor choice; the installer warns and still uses the path the
operator passed. This module does not start schtasks unless asked on Windows.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from usbac_py.exceptions import PlatformError, PolicyApplyError, ValidationError
from usbac_py.windows.elevation import is_elevated

TASK_NAME = "UsbAccessControlPyMonitor"


def task_command(python_exe: str, data_dir: str) -> str:
    return f'"{python_exe}" -m usbac_py monitor --data-dir "{data_dir}"'


def install_arguments(python_exe: str, data_dir: str) -> list[str]:
    if not python_exe or '"' in python_exe or not Path(python_exe).is_absolute():
        raise ValidationError("예약 작업에 넣을 Python 경로는 따옴표 없는 절대 경로여야 합니다.")
    if not data_dir or '"' in data_dir or not Path(data_dir).is_absolute():
        raise ValidationError("예약 작업에 넣을 데이터 폴더는 따옴표 없는 절대 경로여야 합니다.")
    return [
        "/Create",
        "/TN",
        TASK_NAME,
        "/SC",
        "ONSTART",
        "/RU",
        "SYSTEM",
        "/RL",
        "HIGHEST",
        "/F",
        "/TR",
        task_command(python_exe, data_dir),
    ]


def uninstall_arguments() -> list[str]:
    return ["/Delete", "/TN", TASK_NAME, "/F"]


def install_warnings(python_exe: str) -> list[str]:
    lowered = python_exe.replace("\\", "/").lower()
    warnings: list[str] = []
    if "appdata" in lowered or "/venv/" in lowered or lowered.endswith("/venv") or "\\venv\\" in python_exe.lower():
        warnings.append(
            "이 Python 경로는 사용자 프로필 안에 있습니다. SYSTEM 시작 작업은 그 경로를 보지 못할 수 있습니다. "
            "컴퓨터 전체 설치의 python.exe 를 쓰는 것이 안전합니다."
        )
    return warnings


def install_task(python_exe: str, data_dir: str) -> list[str]:
    _require_elevated_windows()
    warnings = install_warnings(python_exe)
    completed = _run(["schtasks", *install_arguments(python_exe, data_dir)])
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise PolicyApplyError(f"시작 작업을 등록하지 못했습니다. {detail}".strip())
    return warnings


def uninstall_task() -> None:
    _require_elevated_windows()
    completed = _run(["schtasks", *uninstall_arguments()])
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise PolicyApplyError(f"시작 작업을 제거하지 못했습니다. {detail}".strip())


def _require_elevated_windows() -> None:
    if sys.platform != "win32":
        raise PlatformError("작업 스케줄러 등록은 Windows에서만 가능합니다.")
    if not is_elevated():
        raise PlatformError("작업 스케줄러를 바꾸려면 관리자 권한으로 다시 실행하세요.")


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, capture_output=True, text=True)
