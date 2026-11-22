"""Optional WMI device-change wake. Polling remains the reliable path.

pywin32 is not required. When it is missing, or when the WMI subscription
fails, the monitor still scans every two seconds.
"""

from __future__ import annotations

import sys
import threading
import time


class PollWake:
    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def wait(self, timeout: float, stop_event: threading.Event) -> None:
        stop_event.wait(timeout)


class WmiDeviceWake:
    """Ask WMI for Win32_DeviceChangeEvent and wake the monitor early."""

    def __init__(self) -> None:
        self._signaled = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if sys.platform != "win32":
            return
        self._thread = threading.Thread(target=self._run, name="usbac-py-wmi", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._signaled.set()

    def wait(self, timeout: float, stop_event: threading.Event) -> None:
        deadline = time.monotonic() + timeout
        while not stop_event.is_set() and not self._stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            if self._signaled.wait(min(0.25, remaining)):
                self._signaled.clear()
                return

    def _run(self) -> None:
        try:
            import pythoncom
            import win32com.client
        except ImportError:
            return
        pythoncom.CoInitialize()
        try:
            locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            services = locator.ConnectServer(".", r"root\cimv2")
            # EventType 2 is arrival and 3 is removal. WITHIN 2 is WMI's own poll.
            events = services.ExecNotificationQuery(
                "SELECT * FROM Win32_DeviceChangeEvent WITHIN 2 WHERE EventType = 2 OR EventType = 3"
            )
            while not self._stop.is_set():
                try:
                    events.NextEvent(2000)
                except Exception:
                    if self._stop.is_set():
                        break
                    continue
                self._signaled.set()
        except Exception:
            return
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                return


def create_wake():
    if sys.platform != "win32":
        return PollWake()
    try:
        import win32com.client  # noqa: F401
        import pythoncom  # noqa: F401
    except ImportError:
        return PollWake()
    return WmiDeviceWake()
