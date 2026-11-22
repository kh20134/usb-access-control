"""Errors the CLI maps onto stable exit codes."""


class UsbAccessControlError(Exception):
    """Base error for this tool. CLI exit code 1."""


class AuthorizationError(UsbAccessControlError):
    """Admin password check failed. CLI exit code 2."""


class ValidationError(UsbAccessControlError):
    """The request or the policy file is not usable. CLI exit code 3."""


class PolicyApplyError(UsbAccessControlError):
    """A policy was not applied. No further registry writes are attempted."""


class DeviceControlError(UsbAccessControlError):
    """A device node could not be changed. Non-storage devices are refused."""

    def __init__(self, message: str, *, device_missing: bool = False) -> None:
        super().__init__(message)
        self.device_missing = device_missing


class PlatformError(UsbAccessControlError):
    """This operating system or token cannot perform the action. CLI exit code 4."""
