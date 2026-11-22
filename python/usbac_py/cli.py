"""Korean command-line interface for usbac-py."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import threading
import uuid
from pathlib import Path
from typing import Callable, TextIO

from usbac_py import __version__
from usbac_py.exceptions import AuthorizationError, PlatformError, UsbAccessControlError, ValidationError
from usbac_py.host import create_session
from usbac_py.identity import is_usbstor_instance
from usbac_py.models import parse_mode
from usbac_py.monitor import run_monitor
from usbac_py.planner import status_text
from usbac_py.session import PolicySession
from usbac_py.windows.task import TASK_NAME, install_task, uninstall_task
from usbac_py.windows.wake import create_wake

SessionFactory = Callable[..., PolicySession]

HELP = """\
usbac-py — USB 저장장치 접근통제 (Python)

정책
  usbac-py policy show [--json]
  usbac-py policy set <block|readonly|allow>
  usbac-py policy apply --yes [--dry-run]

화이트리스트 (VID/PID 필수, 일련번호 생략 시 해당 제품 전체)
  usbac-py whitelist list [--json]
  usbac-py whitelist add --vid 0781 --pid 5581 [--serial 일련번호] --name 이름 [--note 메모]
  usbac-py whitelist remove --id <guid>

장치, 로그, 암호, 감시
  usbac-py devices [--json]
  usbac-py logs [--limit 20] [--json]
  usbac-py logs export --out audit.csv
  usbac-py password set --new <8자 이상>
  usbac-py password clear
  usbac-py monitor [--once] [--observe]
  usbac-py task install
  usbac-py task uninstall

공통
  --data-dir <폴더>   Windows 기본값: %ProgramData%\\UsbAccessControlPy
  --password <암호>   또는 환경 변수 USBAC_ADMIN_PASSWORD
  차단을 실제로 적용할 때는 --yes 가 필요합니다.
  --dry-run 은 레지스트리와 장치 노드를 바꾸지 않습니다.

종료 코드: 0 성공, 2 암호 거부, 3 사용법, 4 권한 또는 운영 체제, 1 그 외 실패
"""


class SystemEnvironment:
    def getenv(self, name: str) -> str | None:
        return os.environ.get(name)

    def read_secret(self, prompt: str) -> str:
        return getpass.getpass(prompt)

    def interactive(self) -> bool:
        try:
            return sys.stdin.isatty()
        except ValueError:
            return False


class CommandRunner:
    def __init__(
        self,
        session_factory: SessionFactory | None = None,
        environment: SystemEnvironment | None = None,
        stdout: TextIO | None = None,
        stderr: TextIO | None = None,
        task_installer: Callable[[str, str], list[str]] | None = None,
        task_uninstaller: Callable[[], None] | None = None,
        wake_factory: Callable[[], object] | None = None,
        python_executable: str | None = None,
    ) -> None:
        self._sessions = session_factory or create_session
        self._environment = environment or SystemEnvironment()
        self.stdout = stdout or sys.stdout
        self.stderr = stderr or sys.stderr
        self._install_task = task_installer or install_task
        self._uninstall_task = task_uninstaller or uninstall_task
        self._wake_factory = wake_factory or create_wake
        self._python = python_executable or sys.executable

    def run(self, argv: list[str]) -> int:
        try:
            return self._run(argv)
        except SystemExit as exc:
            code = exc.code
            return code if isinstance(code, int) else 0
        except AuthorizationError as exc:
            self.stderr.write(str(exc) + "\n")
            return 2
        except ValidationError as exc:
            self.stderr.write(str(exc) + "\n")
            return 3
        except PlatformError as exc:
            self.stderr.write(str(exc) + "\n")
            return 4
        except PermissionError as exc:
            self.stderr.write(str(exc) + "\n")
            return 4
        except UsbAccessControlError as exc:
            self.stderr.write(str(exc) + "\n")
            return 1

    def _run(self, argv: list[str]) -> int:
        if not argv or argv[0] in {"-h", "--help", "help"}:
            self.stdout.write(HELP)
            return 0 if argv else 3
        if argv[0] in {"-V", "--version"}:
            self.stdout.write(__version__ + "\n")
            return 0
        rest, data_dir, password = _extract_globals(argv)
        if not rest:
            self.stdout.write(HELP)
            return 3
        parser = _parser(self.stderr)
        args = parser.parse_args(rest)
        args.data_dir = data_dir
        args.password = password
        if args.command == "task":
            return self._task(args)
        if args.command in {"policy", "whitelist", "password"} and not _subcommand(args):
            self.stdout.write(HELP)
            return 3
        observe_only = bool(getattr(args, "observe", False))
        session = self._sessions(args.data_dir, observe_only=observe_only)
        password = self._password(session, args)
        if args.command == "policy" and args.policy_command == "show":
            return self._show_policy(session, args.json)
        if args.command == "policy" and args.policy_command == "set":
            return self._set_policy(session, args.mode, password)
        if args.command == "policy" and args.policy_command == "apply":
            return self._apply_policy(session, password, yes=args.yes, dry_run=args.dry_run)
        if args.command == "whitelist" and args.whitelist_command == "list":
            return self._list_whitelist(session, args.json)
        if args.command == "whitelist" and args.whitelist_command == "add":
            return self._add_whitelist(session, args, password)
        if args.command == "whitelist" and args.whitelist_command == "remove":
            return self._remove_whitelist(session, args.id, password)
        if args.command == "devices":
            return self._devices(session, args.json)
        if args.command == "logs" and args.logs_command == "export":
            return self._export_logs(session, args.out)
        if args.command == "logs":
            return self._logs(session, args.limit, args.json)
        if args.command == "password" and args.password_command == "set":
            return self._set_password(session, args.new, password)
        if args.command == "password" and args.password_command == "clear":
            session.clear_admin_password(password)
            self.stdout.write("관리자 암호를 해제했습니다.\n")
            return 0
        if args.command == "monitor":
            return self._monitor(session, once=args.once)
        self.stdout.write(HELP)
        return 3

    def _password(self, session: PolicySession, args: argparse.Namespace) -> str | None:
        if session.document.admin_password is None or not _needs_password(args):
            supplied = args.password or self._environment.getenv("USBAC_ADMIN_PASSWORD")
            return supplied or None
        if args.password:
            return args.password
        from_env = self._environment.getenv("USBAC_ADMIN_PASSWORD")
        if from_env:
            return from_env
        if not self._environment.interactive():
            raise AuthorizationError(
                "관리자 암호가 필요합니다. --password 또는 환경 변수 USBAC_ADMIN_PASSWORD를 사용하세요. "
                "프로세스 목록에 암호가 보이지 않게 하려면 환경 변수를 쓰세요."
            )
        return self._environment.read_secret("관리자 암호: ")

    def _show_policy(self, session: PolicySession, as_json: bool) -> int:
        plan = session.preview()
        if as_json:
            payload = {
                "mode": plan.mode.value,
                "modeKo": plan.mode.korean,
                "passwordRequired": session.document.admin_password is not None,
                "applied": session.document.is_applied,
                "status": status_text(plan.mode, plan, len(session.document.whitelist), session.document.is_applied),
                "notes": list(plan.notes),
                "elevated": session.elevated,
                "controlDevices": session.control_devices,
                "dataDirectory": str(session.data_directory),
                "whitelist": [_whitelist_json(entry) for entry in session.document.whitelist],
            }
            self.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            return 0
        self.stdout.write(
            status_text(plan.mode, plan, len(session.document.whitelist), session.document.is_applied) + "\n"
        )
        self.stdout.write("policy.json이 원하는 상태입니다. '적용됨'은 마지막 적용의 지문이 같을 때입니다.\n")
        for note in plan.notes:
            self.stdout.write("- " + note + "\n")
        drift = session.read_registry_drift()
        if drift:
            if all(item.matches for item in drift):
                self.stdout.write("레지스트리 값이 원하는 정책과 같습니다.\n")
            else:
                self.stdout.write(
                    "레지스트리 값이 원하는 정책과 다릅니다. policy apply로 다시 적용하세요. "
                    "도메인 그룹 정책이 덮어썼을 수 있습니다.\n"
                )
        for warning in session.load_warnings:
            self.stdout.write(warning + "\n")
        if not session.elevated:
            self.stdout.write("지금은 관리자 권한이 없습니다. policy apply 는 Windows 설정을 바꾸지 않고 거부됩니다.\n")
        return 0

    def _set_policy(self, session: PolicySession, mode_text: str, password: str | None) -> int:
        mode = parse_mode(mode_text)
        session.set_mode(mode, password)
        self.stdout.write(f"{mode.korean}으로 저장했습니다. Windows에 반영하려면 policy apply --yes 를 실행하세요.\n")
        return 0

    def _apply_policy(self, session: PolicySession, password: str | None, *, yes: bool, dry_run: bool) -> int:
        if session.document.mode.value == "block" and not yes and not dry_run:
            self.stderr.write(
                "차단 정책을 적용하려면 --yes 를 함께 지정하세요. "
                "화이트리스트가 없으면 USB 저장장치와 이동식 저장 클래스 전체가 차단됩니다.\n"
            )
            return 3
        result = session.apply(password, dry_run=dry_run)
        self.stdout.write(
            status_text(result.plan.mode, result.plan, len(session.document.whitelist), session.document.is_applied)
            + "\n"
        )
        for value in result.plan.registry_values():
            self.stdout.write(f"HKLM\\{value.key_path}\\{value.value_name} = {value.dword}\n")
        for warning in result.warnings:
            self.stdout.write(warning + "\n")
        if dry_run:
            return 0
        return 0 if not result.warnings else 1

    def _list_whitelist(self, session: PolicySession, as_json: bool) -> int:
        entries = session.document.whitelist
        if as_json:
            self.stdout.write(json.dumps([_whitelist_json(entry) for entry in entries], ensure_ascii=False, indent=2) + "\n")
            return 0
        if not entries:
            self.stdout.write("화이트리스트가 비어 있습니다.\n")
            return 0
        for entry in entries:
            serial = entry.serial_number or "*"
            self.stdout.write(f"{entry.id}\t{entry.vendor_id}:{entry.product_id}\t{serial}\t{entry.display_name}\n")
        return 0

    def _add_whitelist(self, session: PolicySession, args: argparse.Namespace, password: str | None) -> int:
        entry = session.add_whitelist(args.vid or "", args.pid or "", args.serial, args.name or "", args.note, password)
        self.stdout.write(f"{entry.id} 항목을 저장했습니다. Windows에 반영하려면 policy apply 를 실행하세요.\n")
        return 0

    def _remove_whitelist(self, session: PolicySession, raw_id: str | None, password: str | None) -> int:
        if not raw_id:
            self.stderr.write("사용법: usbac-py whitelist remove --id <guid>\n")
            return 3
        try:
            entry_id = uuid.UUID(raw_id)
        except ValueError:
            self.stderr.write("사용법: usbac-py whitelist remove --id <guid>\n")
            return 3
        removed = session.remove_whitelist(entry_id, password)
        self.stdout.write(
            "항목을 삭제했습니다. Windows에 반영하려면 policy apply 를 실행하세요.\n"
            if removed
            else "해당 항목이 없습니다.\n"
        )
        return 0

    def _devices(self, session: PolicySession, as_json: bool) -> int:
        devices = [
            device
            for device in session.list_devices()
            if device.is_mass_storage and is_usbstor_instance(device.instance_id)
        ]
        rows = []
        for device in devices:
            access = session.explain(device)
            rows.append(
                {
                    "instanceId": device.instance_id,
                    "vendorId": device.vendor_id,
                    "productId": device.product_id,
                    "serialNumber": device.serial_number,
                    "name": device.friendly_name,
                    "access": access.value,
                    "accessKo": access.korean,
                }
            )
        if as_json:
            self.stdout.write(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
            return 0
        if not rows:
            self.stdout.write("연결된 USB 저장장치가 없습니다.\n")
            return 0
        for row in rows:
            self.stdout.write(
                f"{row['accessKo']}\t{row['vendorId']}:{row['productId']}\t{row['serialNumber']}\t{row['name']}\t{row['instanceId']}\n"
            )
        return 0

    def _logs(self, session: PolicySession, limit: int, as_json: bool) -> int:
        if limit < 1:
            raise ValidationError("로그 개수는 1 이상이어야 합니다.")
        events = session.recent_logs(limit)
        if as_json:
            self.stdout.write(json.dumps([event.to_json() for event in events], ensure_ascii=False, indent=2) + "\n")
            return 0
        for event in events:
            stamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%SZ")
            self.stdout.write(
                f"{stamp}\t{event.user_name}\t{event.action.korean}\t{event.device_name or ''}\t{event.result}\t{event.detail}\n"
            )
        return 0

    def _export_logs(self, session: PolicySession, path: str | None) -> int:
        if not path:
            self.stderr.write("사용법: usbac-py logs export --out audit.csv\n")
            return 3
        session.export_logs(Path(path))
        self.stdout.write(path + "\n")
        return 0

    def _set_password(self, session: PolicySession, new_password: str | None, current: str | None) -> int:
        if not new_password:
            self.stderr.write("사용법: usbac-py password set --new <8자 이상>\n")
            return 3
        session.set_admin_password(current, new_password)
        self.stdout.write("관리자 암호를 저장했습니다. 암호는 PBKDF2 해시로만 기록됩니다.\n")
        return 0

    def _monitor(self, session: PolicySession, *, once: bool) -> int:
        try:
            session.list_devices()
        except PlatformError as exc:
            self.stderr.write(str(exc) + "\n")
            return 4
        stop = threading.Event()

        def _handle_signal(_signum, _frame) -> None:
            stop.set()

        try:
            import signal

            signal.signal(signal.SIGINT, _handle_signal)
        except (ValueError, OSError):
            pass
        try:
            run_monitor(session, self._wake_factory(), self.stdout, stop, once=once)
        except KeyboardInterrupt:
            stop.set()
        return 0

    def _task(self, args: argparse.Namespace) -> int:
        if args.task_command == "install":
            data_dir = str(Path(args.data_dir).expanduser().resolve()) if args.data_dir else str(
                _default_dir()
            )
            warnings = self._install_task(self._python, data_dir)
            for warning in warnings:
                self.stderr.write(warning + "\n")
            self.stdout.write(
                f"시작 작업 '{TASK_NAME}'을 등록했습니다. SYSTEM 권한으로 monitor가 실행됩니다.\n"
            )
            return 0
        if args.task_command == "uninstall":
            self._uninstall_task()
            self.stdout.write(f"시작 작업 '{TASK_NAME}'을 제거했습니다.\n")
            return 0
        self.stderr.write("사용법: usbac-py task install | usbac-py task uninstall\n")
        return 3


def main(argv: list[str] | None = None) -> int:
    runner = CommandRunner()
    return runner.run(list(sys.argv[1:] if argv is None else argv))


def _subcommand(args: argparse.Namespace) -> str | None:
    if args.command == "policy":
        return args.policy_command
    if args.command == "whitelist":
        return args.whitelist_command
    if args.command == "password":
        return args.password_command
    return args.command


def _needs_password(args: argparse.Namespace) -> bool:
    if args.command == "policy" and args.policy_command in {"set", "apply"} and not getattr(args, "dry_run", False):
        return True
    if args.command == "whitelist" and args.whitelist_command in {"add", "remove"}:
        return True
    if args.command == "password":
        return True
    return False


def _whitelist_json(entry) -> dict[str, object]:
    return {
        "id": str(entry.id),
        "vendorId": entry.vendor_id,
        "productId": entry.product_id,
        "serialNumber": entry.serial_number,
        "displayName": entry.display_name,
        "note": entry.note,
    }


def _default_dir():
    from usbac_py.store import default_data_directory

    return default_data_directory()


def _extract_globals(argv: list[str]) -> tuple[list[str], str | None, str | None]:
    data_dir = None
    password = None
    rest: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--data-dir" and index + 1 < len(argv):
            data_dir = argv[index + 1]
            index += 2
            continue
        if token.startswith("--data-dir="):
            data_dir = token.split("=", 1)[1]
            index += 1
            continue
        if token == "--password" and index + 1 < len(argv):
            password = argv[index + 1]
            index += 2
            continue
        if token.startswith("--password="):
            password = token.split("=", 1)[1]
            index += 1
            continue
        rest.append(token)
        index += 1
    return rest, data_dir, password


def _parser(stderr: TextIO) -> argparse.ArgumentParser:
    class Parser(argparse.ArgumentParser):
        def error(self, message: str) -> None:
            stderr.write(message + "\n")
            raise SystemExit(3)

    parser = Parser(prog="usbac-py", add_help=False)
    commands = parser.add_subparsers(dest="command")

    policy = commands.add_parser("policy", add_help=False)
    policy_commands = policy.add_subparsers(dest="policy_command")
    show = policy_commands.add_parser("show", add_help=False)
    show.add_argument("--json", action="store_true")
    set_policy = policy_commands.add_parser("set", add_help=False)
    set_policy.add_argument("mode")
    apply_policy = policy_commands.add_parser("apply", add_help=False)
    apply_policy.add_argument("--yes", action="store_true")
    apply_policy.add_argument("--dry-run", action="store_true")

    whitelist = commands.add_parser("whitelist", add_help=False)
    whitelist_commands = whitelist.add_subparsers(dest="whitelist_command")
    listed = whitelist_commands.add_parser("list", add_help=False)
    listed.add_argument("--json", action="store_true")
    added = whitelist_commands.add_parser("add", add_help=False)
    added.add_argument("--vid")
    added.add_argument("--pid")
    added.add_argument("--serial")
    added.add_argument("--name")
    added.add_argument("--note")
    removed = whitelist_commands.add_parser("remove", add_help=False)
    removed.add_argument("--id")

    devices = commands.add_parser("devices", add_help=False)
    devices.add_argument("--json", action="store_true")

    logs = commands.add_parser("logs", add_help=False)
    logs.add_argument("--limit", type=int, default=20)
    logs.add_argument("--json", action="store_true")
    log_commands = logs.add_subparsers(dest="logs_command")
    exported = log_commands.add_parser("export", add_help=False)
    exported.add_argument("--out")

    password = commands.add_parser("password", add_help=False)
    password_commands = password.add_subparsers(dest="password_command")
    password_set = password_commands.add_parser("set", add_help=False)
    password_set.add_argument("--new")
    password_commands.add_parser("clear", add_help=False)

    monitor = commands.add_parser("monitor", add_help=False)
    monitor.add_argument("--once", action="store_true")
    monitor.add_argument("--observe", action="store_true")

    task = commands.add_parser("task", add_help=False)
    task_commands = task.add_subparsers(dest="task_command")
    task_commands.add_parser("install", add_help=False)
    task_commands.add_parser("uninstall", add_help=False)
    return parser
