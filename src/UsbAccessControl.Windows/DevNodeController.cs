using UsbAccessControl.Core;

namespace UsbAccessControl.Windows;

public sealed class DevNodeController : IDeviceController
{
    public DeviceControlOutcome SetMassStorageEnabled(string instanceId, bool enabled)
    {
        DeviceControlGuard.EnsureUsbStorInstance(instanceId);
        var normalized = instanceId.Trim();
        if (!TryLocate(normalized, out var device))
        {
            return DeviceControlOutcome.NotFound;
        }

        var result = enabled
            ? NativeCfgMgr32.CM_Enable_DevNode(device, 0)
            : NativeCfgMgr32.CM_Disable_DevNode(device, 0);
        if (result == NativeCfgMgr32.CrSuccess)
        {
            return DeviceControlOutcome.Changed;
        }

        if (result == NativeCfgMgr32.CrNoSuchDevNode)
        {
            return DeviceControlOutcome.NotFound;
        }

        throw new DeviceControlException(
            $"USBSTOR 장치 노드를 {(enabled ? "활성화" : "비활성화")}하지 못했습니다 ({normalized}). CR={result}. 관리자 권한이 필요합니다.");
    }

    private static bool TryLocate(string instanceId, out uint device)
    {
        if (NativeCfgMgr32.CM_Locate_DevNode(out device, instanceId, NativeCfgMgr32.LocateNormal) == NativeCfgMgr32.CrSuccess)
        {
            return true;
        }

        return NativeCfgMgr32.CM_Locate_DevNode(out device, instanceId, NativeCfgMgr32.LocatePhantom) == NativeCfgMgr32.CrSuccess;
    }
}
