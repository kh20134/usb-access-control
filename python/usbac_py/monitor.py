"""Polling monitor. WMI, when available, only wakes the loop sooner."""

from __future__ import annotations

import threading
from typing import TextIO

from usbac_py.exceptions import DeviceControlError, PlatformError
from usbac_py.session import PolicySession


def run_monitor(
    session: PolicySession,
    wake,
    output: TextIO,
    stop_event: threading.Event,
    *,
    once: bool = False,
) -> None:
    output.write("USB 저장장치 감시를 시작했습니다. 종료하려면 Ctrl+C 를 누르세요.\n")
    if not session.control_devices:
        output.write(
            "관찰 모드입니다. 장치와 예상 접근을 기록하지만 HKLM과 장치 노드는 바꾸지 않습니다. "
            "실제 차단·읽기 전용 적용은 관리자 권한의 policy apply 와 감시 프로세스가 필요합니다.\n"
        )
    try:
        wake.start()
    except (DeviceControlError, PlatformError, OSError) as exc:
        output.write(str(exc) + "\n")
    session.mark_monitor(True)
    try:
        while not stop_event.is_set():
            try:
                scan = session.scan_and_enforce()
            except (DeviceControlError, PlatformError, OSError) as exc:
                output.write(str(exc) + "\n")
            else:
                for warning in scan.warnings:
                    output.write(warning + "\n")
                for action in scan.actions:
                    result = scan.control_results.get(action.instance_id, "")
                    name = action.device.friendly_name if action.device is not None else ""
                    output.write(f"{action.access.korean}\t{name}\t{result}\t{action.reason}\n")
            if once:
                break
            wake.wait(2.0, stop_event)
    finally:
        try:
            wake.stop()
        finally:
            session.mark_monitor(False)
