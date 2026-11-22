import io
import json
import sys
from pathlib import Path

import pytest

from usbac_py.cli import CommandRunner
from usbac_py.exceptions import DeviceControlError, PlatformError
from usbac_py.host import create_session
from usbac_py.planner import USBSTOR_KEY, USBSTOR_START
from usbac_py.windows.acl import is_managed_directory, protect_arguments
from usbac_py.windows.setupapi import GUID, SP_DEVINFO_DATA, disk_class_guid
from usbac_py.windows.task import install_arguments, install_warnings, task_command, uninstall_arguments
from tests.support import build_session, prepared_registry


class MapEnvironment:
    def __init__(self, values: dict[str, str] | None = None, interactive: bool = False) -> None:
        self.values = values or {}
        self.prompts: list[str] = []
        self._interactive = interactive

    def getenv(self, name: str) -> str | None:
        return self.values.get(name)

    def read_secret(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return "from-prompt-should-not-run"

    def interactive(self) -> bool:
        return self._interactive


def _runner(tmp_path: Path, **kwargs):
    stdout = io.StringIO()
    stderr = io.StringIO()

    def factory(data_dir, observe_only=False):
        directory = Path(data_dir) if data_dir else tmp_path
        session, _registry, _controller, devices = build_session(
            directory,
            elevated=False,
            registry=prepared_registry(),
        )
        devices.devices.append(
            __import__("usbac_py.models", fromlist=["UsbStorageDevice"]).UsbStorageDevice(
                instance_id=r"USBSTOR\DISK&VEN_X\SERIAL&0",
                vendor_id="0781",
                product_id="5581",
                serial_number="ABC",
                friendly_name="Ultra",
                is_mass_storage=True,
            )
        )
        if observe_only:
            session.control_devices = False
        return session

    runner = CommandRunner(
        session_factory=factory,
        environment=kwargs.get("environment") or MapEnvironment(),
        stdout=stdout,
        stderr=stderr,
        task_installer=kwargs.get("task_installer", lambda *_args: []),
        task_uninstaller=kwargs.get("task_uninstaller", lambda: None),
        python_executable=r"C:\Python312\python.exe" if sys.platform == "win32" else "/usr/bin/python3",
    )
    return runner, stdout, stderr


def test_cli_help_and_policy_whitelist_password_flow(tmp_path: Path):
    runner, stdout, stderr = _runner(tmp_path)
    assert runner.run([]) == 3
    assert "usbac-py" in stdout.getvalue()
    stdout.seek(0)
    stdout.truncate(0)
    assert runner.run(["--help"]) == 0
    assert runner.run(["--version"]) == 0
    assert runner.run(["--data-dir", str(tmp_path), "policy", "set", "readonly"]) == 0
    assert "읽기 전용" in stdout.getvalue()
    assert runner.run(["--data-dir", str(tmp_path), "whitelist", "add", "--vid", "0781", "--pid", "5581", "--name", "승인"]) == 0
    assert runner.run(["--data-dir", str(tmp_path), "password", "set", "--new", "correct-horse"]) == 0
    assert "correct-horse" not in (tmp_path / "policy.json").read_text(encoding="utf-8")
    code = runner.run(["--data-dir", str(tmp_path), "whitelist", "add", "--vid", "0951", "--pid", "1666", "--name", "다른"])
    assert code == 2
    assert "암호" in stderr.getvalue()
    env = MapEnvironment({"USBAC_ADMIN_PASSWORD": "correct-horse"})
    runner, stdout, stderr = _runner(tmp_path, environment=env)
    assert runner.run(["--data-dir", str(tmp_path), "policy", "set", "block"]) == 0
    stdout.seek(0)
    stdout.truncate(0)
    assert runner.run(["--data-dir", str(tmp_path), "policy", "show", "--json"]) == 0
    payload = json.loads(stdout.getvalue())
    assert payload["mode"] == "block"
    assert payload["passwordRequired"] is True
    assert "hashBase64" not in stdout.getvalue()
    assert "saltBase64" not in stdout.getvalue()
    assert runner.run(["--data-dir", str(tmp_path), "policy", "apply", "--dry-run"]) == 0
    assert runner.run(["--data-dir", str(tmp_path), "policy", "apply"]) == 3
    assert runner.run(["--data-dir", str(tmp_path), "devices"]) == 0
    assert "Ultra" in stdout.getvalue()
    assert runner.run(["--data-dir", str(tmp_path), "logs", "export", "--out", str(tmp_path / "audit.csv")]) == 0
    exported = (tmp_path / "audit.csv").read_text(encoding="utf-8-sig")
    assert "whitelistAdded" in (tmp_path / "audit.jsonl").read_text(encoding="utf-8") or "화이트리스트" in exported
    assert runner.run(["--data-dir", str(tmp_path), "monitor", "--once", "--observe"]) == 0
    assert "관찰" in stdout.getvalue() or "차단" in stdout.getvalue()


def test_real_host_refuses_to_apply_when_not_elevated(tmp_path: Path):
    session = create_session(str(tmp_path))
    if session.elevated:
        pytest.skip("this process is elevated; the test must not write HKLM")
    session.set_mode(__import__("usbac_py.models", fromlist=["PolicyMode"]).PolicyMode.ALLOW, None)
    with pytest.raises(PlatformError):
        session.apply(None)
    assert session.document.applied_at is None
    if sys.platform != "win32":
        with pytest.raises(PlatformError):
            session.list_devices()


def test_task_arguments_are_absolute_and_distinct_from_the_dotnet_task():
    python_exe = r"C:\Python312\python.exe" if sys.platform == "win32" else "/usr/bin/python3"
    data_dir = r"C:\ProgramData\UsbAccessControlPy" if sys.platform == "win32" else "/tmp/UsbAccessControlPy"
    args = install_arguments(python_exe, data_dir)
    assert args[args.index("/TN") + 1] == "UsbAccessControlPyMonitor"
    assert "UsbAccessControlMonitor" not in args
    assert "/RU" in args and "SYSTEM" in args
    assert task_command(python_exe, data_dir) in args
    assert uninstall_arguments()[:2] == ["/Delete", "/TN"]
    with pytest.raises(Exception):
        install_arguments("python", data_dir)
    warnings = install_warnings(r"C:\Users\someone\AppData\Local\venv\Scripts\python.exe")
    assert warnings


def test_setupapi_structure_matches_pointer_width_and_disk_guid():
    import ctypes

    size = ctypes.sizeof(SP_DEVINFO_DATA)
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert size == 32
    else:
        assert size == 28
    guid = disk_class_guid()
    assert guid.Data1 == 0x4D36E967
    assert guid.Data2 == 0xE325
    assert bytes(guid.Data4) == bytes([0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18])
    assert ctypes.sizeof(GUID) == 16


def test_devnode_refuses_non_storage_before_native_calls():
    from usbac_py.windows.devnode import DevNodeController

    with pytest.raises(DeviceControlError, match="USBSTOR"):
        DevNodeController().set_mass_storage_enabled(r"USB\VID_046D&PID_C52B\MOUSE", False)


@pytest.mark.skipif(sys.platform == "win32", reason="must not touch HKLM")
def test_winreg_editor_refuses_to_run_off_windows():
    from usbac_py.windows.registry import WinregEditor

    with pytest.raises(PlatformError):
        WinregEditor().set_dword(USBSTOR_KEY, USBSTOR_START, 4)


def test_acl_arguments_only_describe_the_managed_folder(tmp_path: Path):
    managed = tmp_path / "UsbAccessControlPy"
    managed.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    assert is_managed_directory(managed, tmp_path)
    assert not is_managed_directory(other, tmp_path)
    arguments = protect_arguments(str(managed))
    assert arguments[0] == "icacls"
    assert "*S-1-5-32-544:(OI)(CI)F" in arguments
    assert "*S-1-5-18:(OI)(CI)F" in arguments
    assert "Everyone" not in " ".join(arguments)
