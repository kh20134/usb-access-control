namespace UsbAccessControl.Core;

public static class WhitelistRules
{
    public const int MaxEntries = 500;
    public const int MaxNameLength = 80;
    public const int MaxNoteLength = 200;
    public const int MaxSerialLength = 128;

    public static WhitelistEntry Create(
        string vendorId,
        string productId,
        string? serialNumber,
        string displayName,
        string? note,
        DateTimeOffset createdAt,
        Guid? id = null)
    {
        var vid = DeviceIdNormalizer.NormalizeVidPid(vendorId)
            ?? throw new ValidationException("VID는 1~4자리 16진수여야 합니다. 예: 0781");
        var pid = DeviceIdNormalizer.NormalizeVidPid(productId)
            ?? throw new ValidationException("PID는 1~4자리 16진수여야 합니다. 예: 5581");
        var serial = DeviceIdNormalizer.NormalizeSerial(serialNumber);
        if (serial is { Length: > MaxSerialLength })
        {
            throw new ValidationException($"일련번호는 {MaxSerialLength}자 이하여야 합니다.");
        }

        var name = (displayName ?? "").Trim();
        if (name.Length == 0)
        {
            throw new ValidationException("표시 이름을 입력하세요.");
        }

        if (name.Length > MaxNameLength)
        {
            throw new ValidationException($"표시 이름은 {MaxNameLength}자 이하여야 합니다.");
        }

        var trimmedNote = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
        if (trimmedNote is { Length: > MaxNoteLength })
        {
            throw new ValidationException($"메모는 {MaxNoteLength}자 이하여야 합니다.");
        }

        return new WhitelistEntry
        {
            Id = id ?? Guid.NewGuid(),
            VendorId = vid,
            ProductId = pid,
            SerialNumber = serial,
            DisplayName = name,
            Note = trimmedNote,
            CreatedAt = createdAt
        };
    }

    public static bool IsSameIdentity(WhitelistEntry left, WhitelistEntry right) =>
        string.Equals(left.VendorId, right.VendorId, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.ProductId, right.ProductId, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.SerialNumber ?? "", right.SerialNumber ?? "", StringComparison.OrdinalIgnoreCase);
}

public static class WhitelistMatcher
{
    public static WhitelistEntry? FindMatch(IReadOnlyList<WhitelistEntry> entries, UsbStorageDevice device)
    {
        var vendorId = DeviceIdNormalizer.NormalizeVidPid(device.VendorId);
        var productId = DeviceIdNormalizer.NormalizeVidPid(device.ProductId);
        if (vendorId is null || productId is null)
        {
            return null;
        }

        var serial = DeviceIdNormalizer.NormalizeSerial(device.SerialNumber);
        WhitelistEntry? wildcard = null;
        foreach (var entry in entries)
        {
            if (!string.Equals(entry.VendorId, vendorId, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(entry.ProductId, productId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var entrySerial = DeviceIdNormalizer.NormalizeSerial(entry.SerialNumber);
            if (entrySerial is null)
            {
                wildcard ??= entry;
                continue;
            }

            if (serial is not null && string.Equals(entrySerial, serial, StringComparison.OrdinalIgnoreCase))
            {
                return entry;
            }
        }

        return wildcard;
    }
}
