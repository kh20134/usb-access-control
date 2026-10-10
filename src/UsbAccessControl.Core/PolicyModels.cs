namespace UsbAccessControl.Core;

public enum PolicyMode
{
    Block = 0,
    ReadOnly = 1,
    Allow = 2
}

public static class PolicyModeNames
{
    public static string ToKorean(this PolicyMode mode) => mode switch
    {
        PolicyMode.Block => "차단",
        PolicyMode.ReadOnly => "읽기 전용",
        PolicyMode.Allow => "허용",
        _ => "차단"
    };

    public static bool TryParse(string? text, out PolicyMode mode)
    {
        mode = PolicyMode.Block;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var value = text.Trim();
        if (value.Equals("block", StringComparison.OrdinalIgnoreCase) || value == "차단")
        {
            mode = PolicyMode.Block;
            return true;
        }

        if (value.Equals("readonly", StringComparison.OrdinalIgnoreCase)
            || value.Equals("read-only", StringComparison.OrdinalIgnoreCase)
            || value is "읽기전용" or "읽기 전용")
        {
            mode = PolicyMode.ReadOnly;
            return true;
        }

        if (value.Equals("allow", StringComparison.OrdinalIgnoreCase) || value == "허용")
        {
            mode = PolicyMode.Allow;
            return true;
        }

        return false;
    }
}

public sealed class PasswordRecord
{
    public string Algorithm { get; set; } = "";
    public int Iterations { get; set; }
    public string SaltBase64 { get; set; } = "";
    public string HashBase64 { get; set; } = "";
}

public sealed class WhitelistEntry
{
    public Guid Id { get; set; }
    public string VendorId { get; set; } = "";
    public string ProductId { get; set; } = "";
    public string? SerialNumber { get; set; }
    public string DisplayName { get; set; } = "";
    public string? Note { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class PolicyDocument
{
    public const int CurrentVersion = 1;

    public int Version { get; set; } = CurrentVersion;
    public PolicyMode Mode { get; set; } = PolicyMode.Block;
    public List<WhitelistEntry> Whitelist { get; set; } = new();
    public PasswordRecord? AdminPassword { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }
    public DateTimeOffset? AppliedAt { get; set; }
    public string? AppliedFingerprint { get; set; }

    public string DesiredFingerprint() => PolicyFingerprint.Compute(this);

    public bool IsApplied => string.Equals(AppliedFingerprint, DesiredFingerprint(), StringComparison.Ordinal);
}

public static class PolicyFingerprint
{
    public static string Compute(PolicyDocument document)
    {
        var entries = document.Whitelist
            .OrderBy(entry => entry.VendorId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(entry => entry.ProductId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(entry => entry.SerialNumber ?? "", StringComparer.OrdinalIgnoreCase)
            .ThenBy(entry => entry.Id);

        var body = string.Join(
            ";",
            entries.Select(entry =>
                $"{entry.VendorId}:{entry.ProductId}:{entry.SerialNumber ?? "*"}:{entry.Id:N}"));
        return $"{document.Mode}|{body}";
    }
}
