using System.Runtime.InteropServices;

namespace UsbAccessControl.Windows;

internal static class NativeSetupApi
{
    public static readonly Guid DiskClass = new("4d36e967-e325-11ce-bfc1-08002be10318");
    public const uint DigcfPresent = 0x02;
    public const uint SpdrpDeviceDesc = 0;
    public const uint SpdrpFriendlyName = 12;
    public const int ErrorInsufficientBuffer = 122;

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SetupDiGetClassDevs(
        ref Guid classGuid,
        string? enumerator,
        IntPtr hwndParent,
        uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiEnumDeviceInfo(
        IntPtr deviceInfoSet,
        uint memberIndex,
        ref SpDevinfoData deviceInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiGetDeviceInstanceId(
        IntPtr deviceInfoSet,
        ref SpDevinfoData deviceInfoData,
        char[] deviceInstanceId,
        int deviceInstanceIdSize,
        out int requiredSize);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool SetupDiGetDeviceRegistryProperty(
        IntPtr deviceInfoSet,
        ref SpDevinfoData deviceInfoData,
        uint property,
        out uint propertyRegDataType,
        byte[] propertyBuffer,
        uint propertyBufferSize,
        out uint requiredSize);

    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [StructLayout(LayoutKind.Sequential)]
    public struct SpDevinfoData
    {
        public uint CbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }
}

internal static class NativeCfgMgr32
{
    public const int CrSuccess = 0;
    public const int CrNoSuchDevNode = 13;
    public const uint LocateNormal = 0;
    public const uint LocatePhantom = 1;

    [DllImport("cfgmgr32.dll")]
    public static extern int CM_Get_Parent(out uint parent, uint device, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    public static extern int CM_Get_Device_ID(uint device, char[] buffer, int bufferLength, uint flags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    public static extern int CM_Locate_DevNode(out uint device, string deviceId, uint flags);

    [DllImport("cfgmgr32.dll")]
    public static extern int CM_Disable_DevNode(uint device, uint flags);

    [DllImport("cfgmgr32.dll")]
    public static extern int CM_Enable_DevNode(uint device, uint flags);
}
