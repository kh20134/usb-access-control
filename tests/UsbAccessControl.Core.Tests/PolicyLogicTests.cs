using UsbAccessControl.Core;

namespace UsbAccessControl.Core.Tests;

public class DeviceIdTests
{
    [Theory]
    [InlineData("0781", "0781")]
    [InlineData("0x781", "0781")]
    [InlineData("vid_78", "0078")]
    [InlineData("PID_00ef", "00EF")]
    [InlineData("gggg", null)]
    [InlineData("", null)]
    [InlineData("12345", null)]
    public void VidPid_is_normalized_or_rejected(string raw, string? expected) =>
        Assert.Equal(expected, DeviceIdNormalizer.NormalizeVidPid(raw));

    [Fact]
    public void Parser_reads_usb_and_usbstor_ids()
    {
        var usb = DeviceIdParser.Parse(@"USB\VID_0781&PID_5581\4C530001230101123456");
        Assert.Equal("0781", usb.VendorId);
        Assert.Equal("5581", usb.ProductId);
        Assert.Equal("4C530001230101123456", usb.SerialNumber);

        var stor = DeviceIdParser.Parse(@"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001230101123456&0");
        Assert.Null(stor.VendorId);
        Assert.Null(stor.ProductId);
        Assert.Equal("4C530001230101123456", stor.SerialNumber);
        Assert.True(DeviceIdParser.IsUsbStorInstance(stor.SerialNumber is null ? "" : @"USBSTOR\DISK&VEN_X\SERIAL&1"));
    }

    [Fact]
    public void Guard_rejects_non_storage_instances()
    {
        var error = Assert.Throws<DeviceControlException>(() =>
            DeviceControlGuard.EnsureUsbStorInstance(@"USB\VID_046D&PID_C52B\MOUSE"));
        Assert.Contains("USBSTOR", error.Message);
    }
}

public class WhitelistMatcherTests
{
    [Fact]
    public void Specific_serial_wins_over_wildcard_and_missing_vid_fails_closed()
    {
        var now = DateTimeOffset.Parse("2026-10-10T00:00:00Z");
        var wildcard = WhitelistRules.Create("781", "5581", null, "제품 전체", null, now);
        var specific = WhitelistRules.Create("0781", "0x5581", "ABC&0", "특정 장치", null, now);
        var entries = new[] { wildcard, specific };

        var exact = WhitelistMatcher.FindMatch(entries, Device("0781", "5581", "abc"));
        var otherSerial = WhitelistMatcher.FindMatch(entries, Device("0781", "5581", "zzz"));
        var missing = WhitelistMatcher.FindMatch(entries, Device(null, "5581", "abc"));

        Assert.Equal(specific.Id, exact!.Id);
        Assert.Equal("ABC", specific.SerialNumber);
        Assert.Equal(wildcard.Id, otherSerial!.Id);
        Assert.Null(missing);
    }

    [Fact]
    public void Duplicate_identity_uses_normalized_serial()
    {
        var now = DateTimeOffset.UnixEpoch;
        var left = WhitelistRules.Create("0781", "5581", "abc", "a", null, now);
        var right = WhitelistRules.Create("0781", "5581", "ABC", "b", null, now);
        Assert.True(WhitelistRules.IsSameIdentity(left, right));
        Assert.Throws<ValidationException>(() => WhitelistRules.Create("0781", "5581", "abc", " ", null, now));
    }

    private static UsbStorageDevice Device(string? vid, string? pid, string? serial) => new()
    {
        InstanceId = @"USBSTOR\DISK&VEN_X\SERIAL&0",
        VendorId = vid,
        ProductId = pid,
        SerialNumber = serial,
        IsMassStorage = true
    };
}

public class EnforcementPlannerTests
{
    [Fact]
    public void Block_without_whitelist_uses_global_deny()
    {
        var plan = EnforcementPlanner.Create(PolicyMode.Block, hasWhitelistEntries: false);
        Assert.Equal(4, plan.UsbStorStart);
        Assert.True(plan.DenyAll);
        Assert.True(plan.DenyRead);
        Assert.True(plan.DenyWrite);
        Assert.False(plan.SelectiveDeviceControl);
        Assert.False(plan.WriteProtect);
        Assert.Contains(plan.RegistryValues(), value => value.ValueName == "Deny_All" && value.Dword == 1);
    }

    [Fact]
    public void Block_with_whitelist_does_not_set_global_deny()
    {
        var plan = EnforcementPlanner.Create(PolicyMode.Block, hasWhitelistEntries: true);
        Assert.Equal(3, plan.UsbStorStart);
        Assert.False(plan.DenyAll);
        Assert.False(plan.DenyRead);
        Assert.False(plan.DenyWrite);
        Assert.False(plan.WriteProtect);
        Assert.True(plan.SelectiveDeviceControl);
        Assert.All(plan.RegistryValues().Where(value => value.ValueName != "Start"), value => Assert.Equal(0, value.Dword));
    }

    [Fact]
    public void ReadOnly_is_global_and_does_not_exempt_whitelist_writes()
    {
        var plan = EnforcementPlanner.Create(PolicyMode.ReadOnly, hasWhitelistEntries: true);
        Assert.False(plan.DenyAll);
        Assert.False(plan.DenyRead);
        Assert.True(plan.DenyWrite);
        Assert.True(plan.WriteProtect);
        Assert.False(plan.SelectiveDeviceControl);
        Assert.True(plan.WhitelistWriteExemptionUnsupported);
        Assert.Equal(EffectiveAccess.ReadOnly, AccessDecider.Enforceable(plan, whitelisted: true));
        Assert.Equal(EffectiveAccess.Allow, AccessDecider.Intended(PolicyMode.ReadOnly, whitelisted: true));
    }

    [Fact]
    public void Allow_clears_restrictions()
    {
        var plan = EnforcementPlanner.Create(PolicyMode.Allow, hasWhitelistEntries: false);
        Assert.Equal(3, plan.UsbStorStart);
        Assert.All(plan.RegistryValues().Where(value => value.ValueName != "Start"), value => Assert.Equal(0, value.Dword));
        Assert.Contains("허용", PolicyStatusText.Build(new PolicyDocument { Mode = PolicyMode.Allow }, plan));
    }

    [Theory]
    [InlineData("block", PolicyMode.Block)]
    [InlineData("읽기 전용", PolicyMode.ReadOnly)]
    [InlineData("read-only", PolicyMode.ReadOnly)]
    [InlineData("허용", PolicyMode.Allow)]
    public void Mode_names_parse(string text, PolicyMode mode)
    {
        Assert.True(PolicyModeNames.TryParse(text, out var parsed));
        Assert.Equal(mode, parsed);
    }

    [Fact]
    public void Missing_usbstor_key_writes_nothing()
    {
        var registry = new MemoryRegistry();
        var plan = EnforcementPlanner.Create(PolicyMode.Allow, false);
        var error = Assert.Throws<PolicyApplyException>(() => RegistryPlanApplier.Apply(plan, registry));
        Assert.Empty(registry.Values);
        Assert.Contains("USBSTOR", error.Message);
    }

    [Fact]
    public void Applier_writes_expected_dwords_when_usbstor_exists()
    {
        var registry = new MemoryRegistry { Keys = { RegistryPolicyPaths.UsbStor } };
        var plan = EnforcementPlanner.Create(PolicyMode.ReadOnly, false);
        RegistryPlanApplier.Apply(plan, registry);
        var drift = RegistryDrift.Compare(plan, registry);
        Assert.All(drift, item => Assert.True(item.Matches));
        Assert.Equal(1, registry.TryGetDword(RegistryPolicyPaths.RemovableDiskKey, RegistryPolicyPaths.DenyWriteValue));
        Assert.Equal(0, registry.TryGetDword(RegistryPolicyPaths.RemovableStorageKey, RegistryPolicyPaths.DenyAllValue));
    }
}

public class SelectiveEnforcementTests
{
    [Fact]
    public void Selective_block_disables_only_non_matching_usbstor_devices()
    {
        var plan = EnforcementPlanner.Create(PolicyMode.Block, true);
        var approved = WhitelistRules.Create("0781", "5581", "OK", "승인", null, DateTimeOffset.UnixEpoch);
        var devices = new[]
        {
            TestSessions.Storage(@"USBSTOR\DISK&VEN_A\OK&0", "0781", "5581", "OK", "approved"),
            TestSessions.Storage(@"USBSTOR\DISK&VEN_B\NO&0", "0951", "1666", "NO", "other"),
            TestSessions.Storage(@"USBSTOR\DISK&VEN_C\UNKNOWN&0", null, null, "UNKNOWN", "no-id"),
            new UsbStorageDevice
            {
                InstanceId = @"USB\VID_046D&PID_C52B\MOUSE",
                VendorId = "046D",
                ProductId = "C52B",
                IsMassStorage = false,
                FriendlyName = "mouse"
            }
        };

        var actions = SelectiveEnforcement.Decide(plan, [approved], devices, []);
        Assert.DoesNotContain(actions, action => action.InstanceId.Contains("MOUSE", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(actions, action => action.InstanceId.Contains("OK", StringComparison.Ordinal) && action.Enable is null && action.Access == EffectiveAccess.Allow);
        Assert.Contains(actions, action => action.InstanceId.Contains("NO", StringComparison.Ordinal) && action.Enable == false);
        Assert.Contains(actions, action => action.InstanceId.Contains("UNKNOWN", StringComparison.Ordinal) && action.Enable == false);
    }

    [Fact]
    public void Leaving_selective_mode_reenables_previously_disabled_devices()
    {
        var plan = EnforcementPlanner.Create(PolicyMode.Allow, false);
        var actions = SelectiveEnforcement.Decide(
            plan,
            [],
            [],
            [@"USBSTOR\DISK&VEN_B\NO&0", @"USB\VID_046D&PID_C52B\MOUSE"]);
        var action = Assert.Single(actions);
        Assert.Equal(@"USBSTOR\DISK&VEN_B\NO&0", action.InstanceId);
        Assert.True(action.Enable);
    }

    [Fact]
    public void Disabled_device_missing_from_the_next_scan_is_not_logged_as_removed()
    {
        var watch = new DeviceWatchService();
        var device = TestSessions.Storage(@"USBSTOR\DISK&VEN_B\NO&0", "0951", "1666", "NO", "other");
        Assert.Equal(DeviceObservationKind.PresentAtStart, Assert.Single(watch.Observe([device])).Kind);

        var second = watch.Observe([], [device.InstanceId]);
        Assert.Empty(second);

        var third = watch.Observe([], []);
        Assert.Equal(DeviceObservationKind.Removed, Assert.Single(third).Kind);
    }
}

public class PasswordAndLogTests
{
    [Fact]
    public void Password_hash_verifies_and_rejects_tampering()
    {
        var salt = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        var record = PasswordHasher.Create("correct-password", salt);
        Assert.True(PasswordHasher.Verify(record, "correct-password"));
        Assert.False(PasswordHasher.Verify(record, "wrong-password"));
        record.HashBase64 = Convert.ToBase64String(new byte[32]);
        Assert.False(PasswordHasher.Verify(record, "correct-password"));
        Assert.Throws<ValidationException>(() => PasswordHasher.Create("short"));
    }

    [Fact]
    public void Audit_log_skips_corrupt_lines_and_csv_neutralizes_formulas()
    {
        var directory = TestSessions.TempDir();
        var log = new AuditLog(directory, new PortableFileProtector());
        log.Append(new AuditEvent
        {
            Timestamp = DateTimeOffset.Parse("2026-10-10T01:02:03Z"),
            UserName = "관리자",
            MachineName = "pc-01",
            Action = AuditAction.DeviceBlocked,
            DeviceName = "=cmd()",
            Detail = "쉼표, \"따옴표\"\n다음 줄",
            Result = "차단"
        });
        File.AppendAllText(log.PathToFile, "{not json\n");
        var events = log.ReadAll();
        var only = Assert.Single(events);
        Assert.Equal("관리자", only.UserName);

        var csv = CsvExporter.Export(events);
        Assert.StartsWith("\uFEFF", csv);
        Assert.Contains("'=cmd()", csv);
        Assert.Contains("\"쉼표, \"\"따옴표\"\"", csv);
        Assert.Contains("정책", AuditAction.PolicyApplied.ToKorean());
    }

    [Fact]
    public void Scheduled_task_arguments_quote_the_executable()
    {
        var exe = OperatingSystem.IsWindows()
            ? @"C:\Program Files\UsbAccessControl\usbac.exe"
            : "/opt/Usb Access/usbac.exe";
        var args = ScheduledTaskDefinition.InstallArguments(exe);
        Assert.Contains("UsbAccessControlMonitor", args);
        Assert.Equal($"\"{exe}\" monitor", args.Last());
        Assert.Throws<ValidationException>(() => ScheduledTaskDefinition.InstallArguments("relative.exe"));
    }
}
