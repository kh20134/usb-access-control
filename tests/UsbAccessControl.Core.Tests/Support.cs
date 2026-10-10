using UsbAccessControl.Core;

namespace UsbAccessControl.Core.Tests;

internal sealed class MutableTimeProvider : TimeProvider
{
    public DateTimeOffset UtcNow { get; set; } = new(2026, 10, 10, 1, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => UtcNow;
}

internal sealed class FakeUser : IUserContext
{
    public string UserName => "admin";
    public string MachineName => "pc-01";
}

internal sealed class MemoryRegistry : IRegistryEditor, IRegistryReader
{
    public HashSet<string> Keys { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, int> Values { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool KeyExists(string keyPath) => Keys.Contains(keyPath);

    public void SetDword(string keyPath, string valueName, int value) =>
        Values[$"{keyPath}|{valueName}"] = value;

    public int? TryGetDword(string keyPath, string valueName) =>
        Values.TryGetValue($"{keyPath}|{valueName}", out var value) ? value : null;
}

internal static class TestSessions
{
    public static string TempDir()
    {
        var path = Path.Combine(Path.GetTempPath(), "usbac-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    public static PolicySession Open(
        string directory,
        IDeviceEnumerator? devices = null,
        IDeviceController? controller = null,
        IPolicyEnforcer? enforcer = null,
        TimeProvider? time = null,
        IRegistryReader? registry = null)
    {
        var protector = new PortableFileProtector();
        return new PolicySession(
            new PolicyStore(directory, protector),
            new AuditLog(directory, protector),
            new EnforcementStateStore(directory, protector),
            new FakeUser(),
            time ?? TimeProvider.System,
            enforcer ?? new RecordingPolicyEnforcer(),
            devices ?? new ScriptedDeviceEnumerator(),
            controller ?? new RecordingDeviceController(),
            new FixedElevation(true),
            SessionOptions.Tests,
            registry);
    }

    public static UsbStorageDevice Storage(
        string instanceId,
        string? vendorId,
        string? productId,
        string? serial,
        string name) => new()
    {
        InstanceId = instanceId,
        VendorId = vendorId,
        ProductId = productId,
        SerialNumber = serial,
        FriendlyName = name,
        IsMassStorage = true
    };
}
