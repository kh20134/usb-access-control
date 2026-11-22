"""In-memory Windows adapters for logic tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from usbac_py.audit import AuditLog
from usbac_py.identity import ensure_usbstor_instance
from usbac_py.models import UsbStorageDevice
from usbac_py.planner import USBSTOR_KEY, apply_plan
from usbac_py.session import PolicySession, UserContext
from usbac_py.store import EnforcementStateStore, PolicyStore


class MemoryRegistry:
    def __init__(self) -> None:
        self.keys: set[str] = set()
        self.values: dict[tuple[str, str], int] = {}

    def key_exists(self, key_path: str) -> bool:
        return key_path.lower() in {item.lower() for item in self.keys}

    def set_dword(self, key_path: str, value_name: str, value: int) -> None:
        self.values[(key_path.lower(), value_name.lower())] = value

    def try_get_dword(self, key_path: str, value_name: str) -> int | None:
        return self.values.get((key_path.lower(), value_name.lower()))


class MemoryDevices:
    def __init__(self, devices: list[UsbStorageDevice] | None = None) -> None:
        self.devices = list(devices or [])

    def list_mass_storage_devices(self) -> list[UsbStorageDevice]:
        return list(self.devices)


class MemoryController:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bool]] = []

    def set_mass_storage_enabled(self, instance_id: str, enabled: bool) -> str:
        normalized = ensure_usbstor_instance(instance_id)
        self.calls.append((normalized, enabled))
        return "changed"


class MemoryEnforcer:
    def __init__(self, registry: MemoryRegistry) -> None:
        self.registry = registry

    def apply(self, plan) -> None:
        apply_plan(plan, self.registry)


def storage(instance_id: str, vendor: str | None, product: str | None, serial: str | None, name: str) -> UsbStorageDevice:
    return UsbStorageDevice(
        instance_id=instance_id,
        vendor_id=vendor,
        product_id=product,
        serial_number=serial,
        friendly_name=name,
        is_mass_storage=True,
    )


def build_session(
    directory: Path,
    *,
    elevated: bool = True,
    devices: list[UsbStorageDevice] | None = None,
    registry: MemoryRegistry | None = None,
    now: datetime | None = None,
) -> tuple[PolicySession, MemoryRegistry, MemoryController, MemoryDevices]:
    registry = registry or MemoryRegistry()
    device_list = MemoryDevices(devices)
    controller = MemoryController()
    clock = lambda: now or datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    session = PolicySession(
        PolicyStore(directory),
        AuditLog(directory),
        EnforcementStateStore(directory),
        UserContext("tester", "test-pc"),
        MemoryEnforcer(registry),
        device_list,
        controller,
        elevated=elevated,
        control_devices=elevated,
        clock=clock,
        registry_reader=registry,
    )
    return session, registry, controller, device_list


def prepared_registry() -> MemoryRegistry:
    registry = MemoryRegistry()
    registry.keys.add(USBSTOR_KEY)
    return registry
