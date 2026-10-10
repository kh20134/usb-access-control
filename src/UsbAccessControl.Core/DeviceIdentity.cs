using System.Text.RegularExpressions;

namespace UsbAccessControl.Core;

public sealed class UsbStorageDevice
{
    public string InstanceId { get; set; } = "";
    public string? VendorId { get; set; }
    public string? ProductId { get; set; }
    public string? SerialNumber { get; set; }
    public string? FriendlyName { get; set; }
    public bool IsMassStorage { get; set; } = true;
}

public readonly record struct ParsedDeviceId(string? VendorId, string? ProductId, string? SerialNumber)
{
    public static ParsedDeviceId Empty { get; } = new(null, null, null);
}

public static partial class DeviceIdNormalizer
{
    public static string? NormalizeVidPid(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var text = raw.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            text = text[2..];
        }

        if (text.StartsWith("VID_", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("PID_", StringComparison.OrdinalIgnoreCase))
        {
            text = text[4..];
        }

        if (text.Length is < 1 or > 4 || !text.All(Uri.IsHexDigit))
        {
            return null;
        }

        return text.ToUpperInvariant().PadLeft(4, '0');
    }

    public static string? NormalizeSerial(string? serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
        {
            return null;
        }

        var text = serial.Trim();
        var separator = text.LastIndexOf('&');
        if (separator > 0 && text[(separator + 1)..].All(char.IsAsciiDigit))
        {
            text = text[..separator];
        }

        return text.Length == 0 ? null : text;
    }
}

public static partial class DeviceIdParser
{
    public static ParsedDeviceId Parse(string? instanceId)
    {
        if (string.IsNullOrWhiteSpace(instanceId))
        {
            return ParsedDeviceId.Empty;
        }

        var id = instanceId.Trim().Replace('/', '\\');
        var vid = VidRegex().Match(id) is { Success: true } vidMatch
            ? vidMatch.Groups[1].Value.ToUpperInvariant()
            : null;
        var pid = PidRegex().Match(id) is { Success: true } pidMatch
            ? pidMatch.Groups[1].Value.ToUpperInvariant()
            : null;

        string? serial = null;
        var parts = id.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 3)
        {
            serial = parts[^1];
            if (parts[0].Equals("USBSTOR", StringComparison.OrdinalIgnoreCase))
            {
                serial = StripUsbStorInstanceSuffix(serial);
            }
        }

        return new ParsedDeviceId(vid, pid, DeviceIdNormalizer.NormalizeSerial(serial));
    }

    public static bool IsUsbStorInstance(string? instanceId) =>
        !string.IsNullOrWhiteSpace(instanceId)
        && instanceId.TrimStart().StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase);

    private static string StripUsbStorInstanceSuffix(string serial)
    {
        var separator = serial.LastIndexOf('&');
        if (separator > 0 && serial[(separator + 1)..].All(char.IsAsciiDigit))
        {
            return serial[..separator];
        }

        return serial;
    }

    [GeneratedRegex(@"VID_([0-9A-Fa-f]{4})", RegexOptions.CultureInvariant)]
    private static partial Regex VidRegex();

    [GeneratedRegex(@"PID_([0-9A-Fa-f]{4})", RegexOptions.CultureInvariant)]
    private static partial Regex PidRegex();
}

public static class DeviceControlGuard
{
    public static void EnsureUsbStorInstance(string instanceId)
    {
        if (!DeviceIdParser.IsUsbStorInstance(instanceId))
        {
            throw new DeviceControlException(
                "USBSTOR 대용량 저장장치만 활성화하거나 비활성화할 수 있습니다. 키보드, 마우스 등 다른 USB 장치는 대상이 아닙니다.");
        }
    }
}
