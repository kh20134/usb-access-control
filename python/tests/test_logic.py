import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from usbac_py.audit import AuditAction, AuditEvent, AuditLog, csv_cell, export_csv
from usbac_py.enforcement import decide_actions
from usbac_py.exceptions import AuthorizationError, DeviceControlError, PlatformError, PolicyApplyError, ValidationError
from usbac_py.identity import ensure_usbstor_instance, normalize_serial, normalize_vid_pid, parse_instance_id
from usbac_py.matcher import create_entry, find_match, same_identity
from usbac_py.models import EffectiveAccess, PolicyMode, UsbStorageDevice, parse_mode
from usbac_py.password import ALGORITHM, create_password, verify_password
from usbac_py.planner import (
    USBSTOR_KEY,
    USBSTOR_START,
    EnforcementPlan,
    PlannedRegistryValue,
    apply_plan,
    assert_policy_value,
    create_plan,
    enforceable_access,
    intended_access,
    removable_disk_key,
)
from usbac_py.store import PolicyStore
from tests.support import build_session, prepared_registry, storage


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0781", "0781"),
        ("0x781", "0781"),
        ("vid_78", "0078"),
        ("PID_00ef", "00EF"),
        ("gggg", None),
        ("", None),
        ("12345", None),
    ],
)
def test_vid_pid_normalization(raw, expected):
    assert normalize_vid_pid(raw) == expected


def test_parser_reads_usb_and_usbstor_ids():
    usb = parse_instance_id(r"USB\VID_0781&PID_5581\4C530001230101123456")
    assert usb.vendor_id == "0781"
    assert usb.product_id == "5581"
    assert usb.serial_number == "4C530001230101123456"

    stor = parse_instance_id(r"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001230101123456&0")
    assert stor.vendor_id is None
    assert stor.product_id is None
    assert stor.serial_number == "4C530001230101123456"
    assert normalize_serial("ABC&0") == "ABC"


def test_guard_rejects_non_storage_instances():
    with pytest.raises(DeviceControlError, match="USBSTOR"):
        ensure_usbstor_instance(r"USB\VID_046D&PID_C52B\MOUSE")


def test_specific_serial_wins_over_wildcard_and_missing_vid_fails_closed():
    now = datetime(2026, 10, 10, tzinfo=timezone.utc)
    wildcard = create_entry("781", "5581", None, "제품 전체", None, now)
    specific = create_entry("0781", "0x5581", "ABC&0", "특정 장치", None, now)
    entries = [wildcard, specific]
    device = UsbStorageDevice(r"USBSTOR\DISK&VEN_X\SERIAL&0", "0781", "5581", "abc", is_mass_storage=True)
    other = UsbStorageDevice(r"USBSTOR\DISK&VEN_X\SERIAL&0", "0781", "5581", "zzz", is_mass_storage=True)
    missing = UsbStorageDevice(r"USBSTOR\DISK&VEN_X\SERIAL&0", None, "5581", "abc", is_mass_storage=True)
    assert find_match(entries, device).id == specific.id
    assert specific.serial_number == "ABC"
    assert find_match(entries, other).id == wildcard.id
    assert find_match(entries, missing) is None


def test_duplicate_identity_uses_normalized_serial():
    now = datetime(1970, 1, 1, tzinfo=timezone.utc)
    left = create_entry("0781", "5581", "abc", "a", None, now)
    right = create_entry("0781", "5581", "ABC", "b", None, now)
    assert same_identity(left, right)
    with pytest.raises(ValidationError):
        create_entry("0781", "5581", "abc", " ", None, now)


def test_mode_names_parse():
    assert parse_mode("block") is PolicyMode.BLOCK
    assert parse_mode("읽기 전용") is PolicyMode.READ_ONLY
    assert parse_mode("read-only") is PolicyMode.READ_ONLY
    assert parse_mode("허용") is PolicyMode.ALLOW
    assert parse_mode("readOnly") is PolicyMode.READ_ONLY


def test_block_without_whitelist_uses_global_deny():
    plan = create_plan(PolicyMode.BLOCK, False)
    assert plan.usbstor_start == 4
    assert plan.deny_all and plan.deny_read and plan.deny_write
    assert not plan.selective_device_control
    assert not plan.write_protect
    assert any(value.value_name == "Deny_All" and value.dword == 1 for value in plan.registry_values())


def test_block_with_whitelist_does_not_set_global_deny():
    plan = create_plan(PolicyMode.BLOCK, True)
    assert plan.usbstor_start == 3
    assert not any([plan.deny_all, plan.deny_read, plan.deny_write, plan.write_protect])
    assert plan.selective_device_control
    assert all(value.dword == 0 for value in plan.registry_values() if value.value_name != "Start")


def test_readonly_is_global_and_does_not_exempt_whitelist_writes():
    plan = create_plan(PolicyMode.READ_ONLY, True)
    assert plan.deny_write and plan.write_protect
    assert not plan.deny_all and not plan.deny_read and not plan.selective_device_control
    assert plan.whitelist_write_exemption_unsupported
    assert enforceable_access(plan, True) is EffectiveAccess.READ_ONLY
    assert intended_access(PolicyMode.READ_ONLY, True) is EffectiveAccess.ALLOW


def test_allow_clears_restrictions():
    plan = create_plan(PolicyMode.ALLOW, False)
    assert plan.usbstor_start == 3
    assert all(value.dword == 0 for value in plan.registry_values() if value.value_name != "Start")


def test_missing_usbstor_key_writes_nothing():
    registry = prepared_registry()
    registry.keys.clear()
    plan = create_plan(PolicyMode.ALLOW, False)
    with pytest.raises(PolicyApplyError, match="USBSTOR"):
        apply_plan(plan, registry)
    assert registry.values == {}


def test_applier_writes_expected_dwords_when_usbstor_exists():
    registry = prepared_registry()
    plan = create_plan(PolicyMode.READ_ONLY, False)
    apply_plan(plan, registry)
    assert registry.try_get_dword(removable_disk_key(), "Deny_Write") == 1
    assert registry.try_get_dword(r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices", "Deny_All") == 0
    assert registry.try_get_dword(USBSTOR_KEY, USBSTOR_START) == 3


def test_applier_rejects_values_outside_the_policy_set():
    with pytest.raises(PolicyApplyError):
        assert_policy_value(PlannedRegistryValue(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Evil", 1))
    rogue = EnforcementPlan(
        mode=PolicyMode.BLOCK,
        whitelist_present=False,
        usbstor_start=1,
        write_protect=False,
        deny_all=False,
        deny_read=False,
        deny_write=False,
        selective_device_control=False,
        whitelist_write_exemption_unsupported=False,
        notes=(),
    )
    registry = prepared_registry()
    with pytest.raises(PolicyApplyError):
        apply_plan(rogue, registry)
    assert registry.values == {}


def test_selective_block_disables_only_non_matching_usbstor_devices():
    plan = create_plan(PolicyMode.BLOCK, True)
    approved = create_entry("0781", "5581", "OK", "승인", None, datetime(1970, 1, 1, tzinfo=timezone.utc))
    devices = [
        storage(r"USBSTOR\DISK&VEN_A\OK&0", "0781", "5581", "OK", "approved"),
        storage(r"USBSTOR\DISK&VEN_B\NO&0", "0951", "1666", "NO", "other"),
        storage(r"USBSTOR\DISK&VEN_C\UNKNOWN&0", None, None, "UNKNOWN", "no-id"),
        UsbStorageDevice(
            instance_id=r"USB\VID_046D&PID_C52B\MOUSE",
            vendor_id="046D",
            product_id="C52B",
            is_mass_storage=False,
            friendly_name="mouse",
        ),
    ]
    actions = decide_actions(plan, [approved], devices, [])
    assert not any("MOUSE" in action.instance_id.upper() for action in actions)
    assert any("OK" in action.instance_id and action.enable is None and action.access is EffectiveAccess.ALLOW for action in actions)
    assert any("NO" in action.instance_id and action.enable is False for action in actions)
    assert any("UNKNOWN" in action.instance_id and action.enable is False for action in actions)


def test_leaving_selective_mode_reenables_previously_disabled_devices():
    plan = create_plan(PolicyMode.ALLOW, False)
    actions = decide_actions(plan, [], [], [r"USBSTOR\DISK&VEN_B\NO&0", r"USB\VID_046D&PID_C52B\MOUSE"])
    assert len(actions) == 1
    assert actions[0].enable is True
    assert actions[0].instance_id.startswith("USBSTOR\\")


def test_password_hash_matches_pbkdf2_vector_and_hides_plaintext():
    record = create_password("correct-horse", salt=b"0123456789abcdef")
    assert record.algorithm == ALGORITHM
    assert record.iterations == 100_000
    assert record.salt_base64 == "MDEyMzQ1Njc4OWFiY2RlZg=="
    assert record.hash_base64 == "focFL/9FDWDoqRCP37JqGQd4Ur13S7/EhD7mVkCcxDQ="
    assert verify_password(record, "correct-horse")
    assert not verify_password(record, "wrong-horse-battery")
    assert not verify_password(record, "")
    record.algorithm = "plain"
    assert not verify_password(record, "correct-horse")
    with pytest.raises(ValidationError):
        create_password("short")


def test_policy_round_trip_and_dotnet_shaped_file(tmp_path: Path):
    store = PolicyStore(tmp_path)
    created = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    entry = create_entry("0781", "5581", "EXAMPLE-SERIAL", "SanDisk", "총무팀", created, uuid.UUID("11111111-1111-1111-1111-111111111111"))
    document = store.load_or_create().document
    document.mode = PolicyMode.READ_ONLY
    document.whitelist = [entry]
    document.admin_password = create_password("correct-horse", salt=b"0123456789abcdef")
    store.save(document)
    text = (tmp_path / "policy.json").read_text(encoding="utf-8")
    assert "correct-horse" not in text
    assert "focFL/9FDWDoqRCP37JqGQd4Ur13S7/EhD7mVkCcxDQ=" in text
    if os.name != "nt":
        mode = stat.S_IMODE((tmp_path / "policy.json").stat().st_mode)
        assert mode == 0o600
    loaded = PolicyStore(tmp_path).load_or_create()
    assert loaded.warnings == ()
    assert loaded.document.mode is PolicyMode.READ_ONLY
    assert loaded.document.whitelist[0].display_name == "SanDisk"
    assert loaded.document.desired_fingerprint().startswith("ReadOnly|0781:5581:EXAMPLE-SERIAL:11111111111111111111111111111111")
    assert verify_password(loaded.document.admin_password, "correct-horse")


def test_store_drops_invalid_entries_and_rejects_future_versions(tmp_path: Path):
    payload = {
        "version": 1,
        "mode": "block",
        "whitelist": [
            {
                "id": "22222222-2222-2222-2222-222222222222",
                "vendorId": "0781",
                "productId": "5581",
                "serialNumber": "KEEP",
                "displayName": "keep",
                "note": None,
                "createdAt": "2026-01-02T03:04:05.1234567+00:00",
            },
            {
                "id": "33333333-3333-3333-3333-333333333333",
                "vendorId": "zzzz",
                "productId": "5581",
                "serialNumber": "DROP",
                "displayName": "drop",
                "note": None,
                "createdAt": "2026-01-02T03:04:05Z",
            },
        ],
        "adminPassword": None,
        "updatedAt": "2026-01-02T03:04:05+00:00",
        "updatedBy": "dotnet",
        "appliedAt": None,
        "appliedFingerprint": None,
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = PolicyStore(tmp_path).load_or_create()
    assert len(loaded.document.whitelist) == 1
    assert loaded.document.whitelist[0].serial_number == "KEEP"
    assert loaded.warnings
    path.write_text(json.dumps({**payload, "version": 9}), encoding="utf-8")
    with pytest.raises(ValidationError, match="버전"):
        PolicyStore(tmp_path).load_or_create()
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ValidationError, match="읽지 못했습니다"):
        PolicyStore(tmp_path).load_or_create()


def test_audit_csv_neutralizes_formulas_and_skips_bad_lines(tmp_path: Path):
    log = AuditLog(tmp_path)
    log.append(
        AuditEvent(
            timestamp=datetime(2026, 1, 2, tzinfo=timezone.utc),
            user_name="tester",
            machine_name="pc",
            action=AuditAction.DEVICE_BLOCKED,
            device_name='=cmd|" /C calc"!A0',
            detail="line",
        )
    )
    with (tmp_path / "audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write("not-json\n")
    events = log.read_all()
    assert len(events) == 1
    csv = export_csv(events)
    assert csv.startswith("\ufeff")
    assert "'=cmd|" in csv
    assert csv_cell("=1+1").startswith("'")
    assert "DeviceBlocked" in csv


def test_session_requires_password_and_does_not_apply_without_elevation(tmp_path: Path):
    session, registry, controller, _devices = build_session(tmp_path, elevated=False, registry=prepared_registry())
    session.set_admin_password(None, "correct-horse")
    with pytest.raises(AuthorizationError):
        session.add_whitelist("0781", "5581", None, "drive", None, "nope")
    session.add_whitelist("0781", "5581", "ABC&0", "drive", None, "correct-horse")
    assert session.document.whitelist[0].serial_number == "ABC"
    with pytest.raises(ValidationError, match="이미"):
        session.add_whitelist("0781", "5581", "abc", "other", None, "correct-horse")
    with pytest.raises(PlatformError):
        session.apply("correct-horse")
    assert session.document.applied_fingerprint is None
    assert registry.values == {}
    assert controller.calls == []
    text = (tmp_path / "policy.json").read_text(encoding="utf-8")
    assert "correct-horse" not in text
    assert any(event.action is AuditAction.POLICY_REJECTED for event in session.recent_logs(10))


def test_elevated_apply_records_fingerprint_and_selective_disable(tmp_path: Path):
    devices = [
        storage(r"USBSTOR\DISK&VEN_A\OK&0", "0781", "5581", "OK", "approved"),
        storage(r"USBSTOR\DISK&VEN_B\NO&0", "0951", "1666", "NO", "other"),
    ]
    session, registry, controller, _devices = build_session(
        tmp_path,
        elevated=True,
        devices=devices,
        registry=prepared_registry(),
    )
    session.add_whitelist("0781", "5581", "OK", "approved", None, None)
    result = session.apply(None)
    assert result.plan.selective_device_control
    assert session.document.is_applied
    assert registry.try_get_dword(USBSTOR_KEY, USBSTOR_START) == 3
    assert controller.calls == [(r"USBSTOR\DISK&VEN_B\NO&0", False)]
    state = json.loads((tmp_path / "enforcement-state.json").read_text(encoding="utf-8"))
    assert state["disabledInstanceIds"] == [r"USBSTOR\DISK&VEN_B\NO&0"]
    dry = session.apply(None, dry_run=True)
    assert dry.warnings
    assert session.document.is_applied
