using System.Text.Json;
using UsbAccessControl.Core;

namespace UsbAccessControl.Core.Tests;

public class PolicySessionTests
{
    [Fact]
    public void Apply_block_with_whitelist_disables_only_unapproved_storage()
    {
        var directory = TestSessions.TempDir();
        var devices = new ScriptedDeviceEnumerator
        {
            Devices =
            [
                TestSessions.Storage(@"USBSTOR\DISK&VEN_SANDISK\OK&0", "0781", "5581", "OK", "SanDisk Ultra"),
                TestSessions.Storage(@"USBSTOR\DISK&VEN_KINGSTON\NO&0", "0951", "1666", "NO", "Kingston DataTraveler"),
                new UsbStorageDevice { InstanceId = @"USB\VID_046D&PID_C52B\MOUSE", IsMassStorage = false, FriendlyName = "Mouse" }
            ]
        };
        var controller = new RecordingDeviceController();
        var enforcer = new RecordingPolicyEnforcer();
        var time = new MutableTimeProvider();
        var session = TestSessions.Open(directory, devices, controller, enforcer, time);

        session.AddWhitelist("0781", "5581", "OK", "SanDisk Ultra", "총무팀", null);
        session.SetMode(PolicyMode.Block, null);
        var result = session.Apply(null);

        Assert.True(result.Plan.SelectiveDeviceControl);
        Assert.True(session.Document.IsApplied);
        var call = Assert.Single(controller.Calls);
        Assert.Equal(@"USBSTOR\DISK&VEN_KINGSTON\NO&0", call.InstanceId);
        Assert.False(call.Enabled);
        Assert.Contains(session.RecentLogs(20), item => item.Action == AuditAction.DeviceBlocked && item.DeviceName == "Kingston DataTraveler");
        Assert.Contains(session.RecentLogs(20), item => item.Action == AuditAction.DeviceAllowed && item.DeviceName == "SanDisk Ultra");
        Assert.Equal(EffectiveAccess.Allow, session.Explain(devices.Devices[0]));
        Assert.Equal(EffectiveAccess.Block, session.Explain(devices.Devices[1]));
    }

    [Fact]
    public void Wrong_password_does_not_change_policy_and_failed_apply_is_not_marked()
    {
        var directory = TestSessions.TempDir();
        var time = new MutableTimeProvider();
        var session = TestSessions.Open(directory, time: time, enforcer: new ThrowingPolicyEnforcer());
        session.SetAdminPassword(null, "correct-password");
        Assert.Throws<AuthorizationException>(() => session.SetMode(PolicyMode.Allow, "nope"));
        Assert.Equal(PolicyMode.Block, session.Document.Mode);
        Assert.Contains(session.RecentLogs(10), item => item.Action == AuditAction.PolicyRejected && item.Result == "거부");

        session.SetMode(PolicyMode.Allow, "correct-password");
        Assert.Throws<PolicyApplyException>(() => session.Apply("correct-password"));
        Assert.False(session.Document.IsApplied);
        Assert.Contains(session.RecentLogs(10), item => item.Action == AuditAction.PolicyRejected && item.Result == "실패");

        var reloaded = TestSessions.Open(directory, time: time, enforcer: new RecordingPolicyEnforcer());
        Assert.Equal(PolicyMode.Allow, reloaded.Document.Mode);
        Assert.False(reloaded.Document.IsApplied);
        Assert.True(PasswordHasher.Verify(reloaded.Document.AdminPassword, "correct-password"));
        var stored = File.ReadAllText(Path.Combine(directory, "policy.json"));
        Assert.DoesNotContain("correct-password", stored);
    }

    [Fact]
    public void Read_only_apply_does_not_disable_whitelisted_device()
    {
        var directory = TestSessions.TempDir();
        var devices = new ScriptedDeviceEnumerator
        {
            Devices = [TestSessions.Storage(@"USBSTOR\DISK&VEN_A\OK&0", "0781", "5581", "OK", "disk")]
        };
        var controller = new RecordingDeviceController();
        var session = TestSessions.Open(directory, devices, controller);
        session.AddWhitelist("0781", "5581", null, "제품", null, null);
        session.SetMode(PolicyMode.ReadOnly, null);
        session.Apply(null);
        Assert.Empty(controller.Calls);
        Assert.Equal(EffectiveAccess.ReadOnly, session.Explain(devices.Devices[0]));
        Assert.Contains("쓸 수 없", PolicyStatusText.Build(session.Document, session.Preview()));
    }

    [Fact]
    public void Allow_reenables_a_device_disabled_by_an_earlier_block()
    {
        var directory = TestSessions.TempDir();
        var devices = new ScriptedDeviceEnumerator
        {
            Devices = [TestSessions.Storage(@"USBSTOR\DISK&VEN_B\NO&0", "0951", "1666", "NO", "other")]
        };
        var controller = new RecordingDeviceController();
        var session = TestSessions.Open(directory, devices, controller);
        session.AddWhitelist("0781", "5581", "OK", "other-product", null, null);
        session.SetMode(PolicyMode.Block, null);
        session.Apply(null);
        Assert.Contains(controller.Calls, call => call.Enabled == false);

        devices.Devices = [];
        session.SetMode(PolicyMode.Allow, null);
        session.Apply(null);
        Assert.Contains(controller.Calls, call => call.Enabled);
    }

    [Fact]
    public void Csv_export_is_logged_and_invalid_whitelist_entry_is_dropped()
    {
        var directory = TestSessions.TempDir();
        var session = TestSessions.Open(directory);
        session.AddWhitelist("0781", "5581", null, "정상", null, null);
        var path = Path.Combine(directory, "policy.json");
        var document = JsonSerializer.Deserialize<PolicyDocument>(File.ReadAllText(path), JsonFormat.Indented)!;
        document.Whitelist.Add(new WhitelistEntry { VendorId = "zz", ProductId = "11", DisplayName = "깨짐" });
        File.WriteAllText(path, JsonSerializer.Serialize(document, JsonFormat.Indented));

        var reloaded = TestSessions.Open(directory);
        Assert.Single(reloaded.Document.Whitelist);
        Assert.NotEmpty(reloaded.LoadWarnings);

        var csv = Path.Combine(directory, "audit.csv");
        reloaded.ExportLogs(csv);
        var bytes = File.ReadAllBytes(csv);
        Assert.Equal(new byte[] { 0xEF, 0xBB, 0xBF }, bytes.Take(3));
        Assert.Contains(reloaded.RecentLogs(20), item => item.Action == AuditAction.LogExported);
    }

    [Fact]
    public void Fingerprint_changes_when_whitelist_changes_but_not_when_password_changes()
    {
        var directory = TestSessions.TempDir();
        var session = TestSessions.Open(directory);
        session.Apply(null);
        var applied = session.Document.AppliedFingerprint;
        session.SetAdminPassword(null, "long-enough");
        Assert.Equal(applied, session.Document.DesiredFingerprint());
        Assert.True(session.Document.IsApplied);
        session.AddWhitelist("0951", "1666", null, "Kingston", null, "long-enough");
        Assert.False(session.Document.IsApplied);
    }
}
