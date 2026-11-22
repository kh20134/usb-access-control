"""Optional ACL lock for the default ProgramData directory.

The lock is not a security boundary against a local administrator. It only
removes inherited access so a standard user who can reach the folder is not
granted it. The directory must already be the tool's own ProgramData folder;
other paths are left alone.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

DIRECTORY_NAME = "UsbAccessControlPy"
ADMINISTRATORS_SID = "S-1-5-32-544"
SYSTEM_SID = "S-1-5-18"


def is_managed_directory(directory: Path, program_data: Path) -> bool:
    try:
        resolved = directory.resolve()
        root = program_data.resolve()
    except OSError:
        return False
    return resolved.name == DIRECTORY_NAME and resolved.parent == root


def protect_arguments(directory: str) -> list[str]:
    return [
        "icacls",
        directory,
        "/inheritance:r",
        "/grant:r",
        f"*{ADMINISTRATORS_SID}:(OI)(CI)F",
        f"*{SYSTEM_SID}:(OI)(CI)F",
    ]


class WindowsAclProtector:
    def __init__(self, program_data: Path | None = None) -> None:
        self.warning: str | None = None
        if program_data is None:
            program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        self._program_data = program_data

    def protect_directory(self, directory: Path) -> None:
        if sys.platform != "win32":
            return
        if not is_managed_directory(directory, self._program_data):
            return
        completed = subprocess.run(
            protect_arguments(str(directory)),
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            self.warning = (
                "정책 폴더 ACL을 Administrators와 SYSTEM으로 잠그지 못했습니다. "
                "정책 파일은 저장했습니다. 로컬 관리자는 어느 쪽이든 파일을 읽을 수 있습니다."
            )

    def protect_file(self, path: Path) -> None:
        return None
