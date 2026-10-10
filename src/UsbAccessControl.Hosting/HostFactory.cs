using System.Runtime.Versioning;
using UsbAccessControl.Core;
using UsbAccessControl.Windows;

namespace UsbAccessControl.Hosting;

public static class HostFactory
{
    public static PolicySession CreateProduction(string? dataDirectory)
    {
        var windows = OperatingSystem.IsWindows();
        var protector = windows ? CreateWindowsProtector() : (IFileProtector)new PortableFileProtector();
        var directory = AppPaths.ResolveDataDirectory(dataDirectory);
        Directory.CreateDirectory(directory);
        protector.ProtectDirectory(directory);
        return Build(
            directory,
            protector,
            windows ? CreateWindowsEnforcer() : new NoOpPolicyEnforcer(),
            windows ? CreateWindowsDevices() : new EmptyDeviceEnumerator(),
            windows ? CreateWindowsController() : new RecordingDeviceController(),
            windows ? CreateWindowsElevation() : new FixedElevation(false),
            new EnvironmentUserContext(),
            SessionOptions.Production,
            windows ? CreateWindowsRegistry() : null);
    }

    public static PolicySession CreatePreview(string directory, IDeviceEnumerator devices)
    {
        var protector = new PortableFileProtector();
        Directory.CreateDirectory(directory);
        protector.ProtectDirectory(directory);
        return Build(
            directory,
            protector,
            new NoOpPolicyEnforcer(),
            devices,
            new RecordingDeviceController(),
            new FixedElevation(false),
            new FixedUserContext("사용자", "예시PC"),
            SessionOptions.Preview,
            registry: null);
    }

    public static IDeviceWakeSignal CreateWakeSignal() =>
        OperatingSystem.IsWindows() ? CreateWindowsWakeSignal() : new NullWakeSignal();

    public static void InstallStartupTask(string exePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("작업 스케줄러 등록은 Windows에서만 가능합니다.");
        }

        InstallStartupTaskCore(exePath);
    }

    public static void UninstallStartupTask()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("작업 스케줄러 제거는 Windows에서만 가능합니다.");
        }

        UninstallStartupTaskCore();
    }

    private static PolicySession Build(
        string directory,
        IFileProtector protector,
        IPolicyEnforcer enforcer,
        IDeviceEnumerator devices,
        IDeviceController controller,
        IElevationProbe elevation,
        IUserContext user,
        SessionOptions options,
        IRegistryReader? registry)
    {
        return new PolicySession(
            new PolicyStore(directory, protector),
            new AuditLog(directory, protector),
            new EnforcementStateStore(directory, protector),
            user,
            TimeProvider.System,
            enforcer,
            devices,
            controller,
            elevation,
            options,
            registry);
    }

    [SupportedOSPlatform("windows")]
    private static IFileProtector CreateWindowsProtector() => new WindowsAclProtector();

    [SupportedOSPlatform("windows")]
    private static IPolicyEnforcer CreateWindowsEnforcer() => new RegistryPolicyEnforcer(new WindowsRegistryEditor());

    [SupportedOSPlatform("windows")]
    private static IDeviceEnumerator CreateWindowsDevices() => new SetupApiDeviceEnumerator();

    [SupportedOSPlatform("windows")]
    private static IDeviceController CreateWindowsController() => new DevNodeController();

    [SupportedOSPlatform("windows")]
    private static IElevationProbe CreateWindowsElevation() => new WindowsElevationProbe();

    [SupportedOSPlatform("windows")]
    private static IRegistryReader CreateWindowsRegistry() => new WindowsRegistryEditor();

    [SupportedOSPlatform("windows")]
    private static IDeviceWakeSignal CreateWindowsWakeSignal() => new WmiDeviceWakeSignal();

    [SupportedOSPlatform("windows")]
    private static void InstallStartupTaskCore(string exePath) => WindowsScheduledTask.Install(exePath);

    [SupportedOSPlatform("windows")]
    private static void UninstallStartupTaskCore() => WindowsScheduledTask.Uninstall();
}
