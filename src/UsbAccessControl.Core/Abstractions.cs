namespace UsbAccessControl.Core;

public interface IPolicyEnforcer
{
    void Apply(EnforcementPlan plan);
}

public interface IDeviceEnumerator
{
    IReadOnlyList<UsbStorageDevice> ListMassStorageDevices();
}

public enum DeviceControlOutcome
{
    Changed,
    NotFound,
    Failed
}

public interface IDeviceController
{
    DeviceControlOutcome SetMassStorageEnabled(string instanceId, bool enabled);
}

public interface IDeviceWakeSignal : IDisposable
{
    event EventHandler? Signaled;
    void Start();
}

public interface IElevationProbe
{
    bool IsElevated { get; }
}

public interface IUserContext
{
    string UserName { get; }
    string MachineName { get; }
}

public sealed record SessionOptions(bool RequireWindowsHost, bool Simulation)
{
    public static SessionOptions Production { get; } = new(true, false);
    public static SessionOptions Preview { get; } = new(false, true);
    public static SessionOptions Tests { get; } = new(false, false);
}

public sealed class EnvironmentUserContext : IUserContext
{
    public string UserName => string.IsNullOrWhiteSpace(Environment.UserName) ? "unknown" : Environment.UserName;
    public string MachineName => string.IsNullOrWhiteSpace(Environment.MachineName) ? "unknown" : Environment.MachineName;
}

public sealed class FixedElevation : IElevationProbe
{
    public FixedElevation(bool isElevated) => IsElevated = isElevated;
    public bool IsElevated { get; }
}

public sealed class NoOpPolicyEnforcer : IPolicyEnforcer
{
    public void Apply(EnforcementPlan plan)
    {
    }
}

public sealed class EmptyDeviceEnumerator : IDeviceEnumerator
{
    public IReadOnlyList<UsbStorageDevice> ListMassStorageDevices() => Array.Empty<UsbStorageDevice>();
}

public sealed class RecordingPolicyEnforcer : IPolicyEnforcer
{
    public List<EnforcementPlan> Plans { get; } = new();

    public void Apply(EnforcementPlan plan) => Plans.Add(plan);
}

public sealed class ThrowingPolicyEnforcer : IPolicyEnforcer
{
    public void Apply(EnforcementPlan plan) => throw new PolicyApplyException("레지스트리 쓰기를 실패로 흉내 냈습니다.");
}

public sealed class RecordingDeviceController : IDeviceController
{
    public List<(string InstanceId, bool Enabled)> Calls { get; } = new();

    public DeviceControlOutcome SetMassStorageEnabled(string instanceId, bool enabled)
    {
        DeviceControlGuard.EnsureUsbStorInstance(instanceId);
        Calls.Add((instanceId, enabled));
        return DeviceControlOutcome.Changed;
    }
}

public sealed class ScriptedDeviceEnumerator : IDeviceEnumerator
{
    public IReadOnlyList<UsbStorageDevice> Devices { get; set; } = Array.Empty<UsbStorageDevice>();

    public IReadOnlyList<UsbStorageDevice> ListMassStorageDevices() => Devices;
}

public sealed class NullWakeSignal : IDeviceWakeSignal
{
    public event EventHandler? Signaled
    {
        add { }
        remove { }
    }

    public void Start()
    {
    }

    public void Dispose()
    {
    }
}
