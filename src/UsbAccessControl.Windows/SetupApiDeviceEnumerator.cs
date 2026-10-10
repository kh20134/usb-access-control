using System.Runtime.InteropServices;
using System.Text;
using UsbAccessControl.Core;

namespace UsbAccessControl.Windows;

public sealed class SetupApiDeviceEnumerator : IDeviceEnumerator
{
    public IReadOnlyList<UsbStorageDevice> ListMassStorageDevices()
    {
        var classGuid = NativeSetupApi.DiskClass;
        var handle = NativeSetupApi.SetupDiGetClassDevs(
            ref classGuid,
            "USBSTOR",
            IntPtr.Zero,
            NativeSetupApi.DigcfPresent);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            throw new DeviceControlException(
                "USBSTOR 장치 목록을 열지 못했습니다. Win32=" + Marshal.GetLastWin32Error());
        }

        var devices = new List<UsbStorageDevice>();
        try
        {
            uint index = 0;
            while (true)
            {
                var info = new NativeSetupApi.SpDevinfoData
                {
                    CbSize = (uint)Marshal.SizeOf<NativeSetupApi.SpDevinfoData>()
                };
                if (!NativeSetupApi.SetupDiEnumDeviceInfo(handle, index, ref info))
                {
                    break;
                }

                index++;
                var instanceId = ReadInstanceId(handle, ref info);
                if (!DeviceIdParser.IsUsbStorInstance(instanceId))
                {
                    continue;
                }

                var parsed = DeviceIdParser.Parse(instanceId);
                var (vendorId, productId) = ResolveVidPid(info.DevInst, parsed);
                devices.Add(new UsbStorageDevice
                {
                    InstanceId = instanceId,
                    VendorId = vendorId,
                    ProductId = productId,
                    SerialNumber = parsed.SerialNumber,
                    FriendlyName = ReadText(handle, ref info, NativeSetupApi.SpdrpFriendlyName)
                        ?? ReadText(handle, ref info, NativeSetupApi.SpdrpDeviceDesc),
                    IsMassStorage = true
                });
            }
        }
        finally
        {
            NativeSetupApi.SetupDiDestroyDeviceInfoList(handle);
        }

        return devices;
    }

    private static (string? VendorId, string? ProductId) ResolveVidPid(uint devInst, ParsedDeviceId parsed)
    {
        if (parsed.VendorId is not null && parsed.ProductId is not null)
        {
            return (parsed.VendorId, parsed.ProductId);
        }

        var current = devInst;
        for (var depth = 0; depth < 8; depth++)
        {
            if (NativeCfgMgr32.CM_Get_Parent(out var parent, current, 0) != NativeCfgMgr32.CrSuccess)
            {
                break;
            }

            var parentId = ReadDeviceId(parent);
            var parentParsed = DeviceIdParser.Parse(parentId);
            if (parentParsed.VendorId is not null && parentParsed.ProductId is not null)
            {
                return (parentParsed.VendorId, parentParsed.ProductId);
            }

            current = parent;
        }

        return (null, null);
    }

    private static string ReadInstanceId(IntPtr handle, ref NativeSetupApi.SpDevinfoData info)
    {
        var buffer = new char[512];
        if (!NativeSetupApi.SetupDiGetDeviceInstanceId(handle, ref info, buffer, buffer.Length, out var required))
        {
            if (required is > 512 and < 4096)
            {
                buffer = new char[required];
                if (!NativeSetupApi.SetupDiGetDeviceInstanceId(handle, ref info, buffer, buffer.Length, out _))
                {
                    return "";
                }
            }
            else
            {
                return "";
            }
        }

        return new string(buffer).TrimEnd('\0');
    }

    private static string? ReadText(IntPtr handle, ref NativeSetupApi.SpDevinfoData info, uint property)
    {
        var buffer = new byte[1024];
        if (!NativeSetupApi.SetupDiGetDeviceRegistryProperty(
                handle,
                ref info,
                property,
                out _,
                buffer,
                (uint)buffer.Length,
                out var required))
        {
            if (Marshal.GetLastWin32Error() == NativeSetupApi.ErrorInsufficientBuffer && required is > 0 and < 8192)
            {
                buffer = new byte[required];
                if (!NativeSetupApi.SetupDiGetDeviceRegistryProperty(
                        handle,
                        ref info,
                        property,
                        out _,
                        buffer,
                        (uint)buffer.Length,
                        out _))
                {
                    return null;
                }
            }
            else
            {
                return null;
            }
        }

        var text = Encoding.Unicode.GetString(buffer);
        var end = text.IndexOf('\0');
        if (end >= 0)
        {
            text = text[..end];
        }

        text = text.Trim();
        return text.Length == 0 ? null : text;
    }

    private static string ReadDeviceId(uint devInst)
    {
        var buffer = new char[512];
        var result = NativeCfgMgr32.CM_Get_Device_ID(devInst, buffer, buffer.Length, 0);
        return result == NativeCfgMgr32.CrSuccess ? new string(buffer).TrimEnd('\0') : "";
    }
}
