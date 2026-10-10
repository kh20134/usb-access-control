using System.Text;
using System.Text.Json;

namespace UsbAccessControl.Core;

public enum AuditAction
{
    PolicyApplied,
    PolicyRejected,
    WhitelistAdded,
    WhitelistRemoved,
    DeviceInserted,
    DeviceRemoved,
    DeviceBlocked,
    DeviceAllowed,
    DeviceReadOnly,
    LogExported,
    PasswordSet,
    PasswordCleared,
    MonitorStarted,
    MonitorStopped
}

public static class AuditActionNames
{
    public static string ToKorean(this AuditAction action) => action switch
    {
        AuditAction.PolicyApplied => "정책 적용",
        AuditAction.PolicyRejected => "정책 거부",
        AuditAction.WhitelistAdded => "화이트리스트 추가",
        AuditAction.WhitelistRemoved => "화이트리스트 삭제",
        AuditAction.DeviceInserted => "장치 연결",
        AuditAction.DeviceRemoved => "장치 분리",
        AuditAction.DeviceBlocked => "장치 차단",
        AuditAction.DeviceAllowed => "장치 허용",
        AuditAction.DeviceReadOnly => "장치 읽기 전용",
        AuditAction.LogExported => "로그 내보내기",
        AuditAction.PasswordSet => "암호 설정",
        AuditAction.PasswordCleared => "암호 해제",
        AuditAction.MonitorStarted => "감시 시작",
        AuditAction.MonitorStopped => "감시 중지",
        _ => action.ToString()
    };
}

public sealed class AuditEvent
{
    public DateTimeOffset Timestamp { get; set; }
    public string UserName { get; set; } = "";
    public string MachineName { get; set; } = "";
    public AuditAction Action { get; set; }
    public string? InstanceId { get; set; }
    public string? VendorId { get; set; }
    public string? ProductId { get; set; }
    public string? SerialNumber { get; set; }
    public string? DeviceName { get; set; }
    public string? PolicyMode { get; set; }
    public string? Result { get; set; }
    public string? Detail { get; set; }
}

public sealed class AuditLog
{
    private readonly string _path;
    private readonly IFileProtector _protector;
    private readonly object _gate = new();

    public AuditLog(string directory, IFileProtector protector)
    {
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "audit.jsonl");
        _protector = protector;
    }

    public string PathToFile => _path;

    public void Append(AuditEvent auditEvent)
    {
        var line = JsonSerializer.Serialize(auditEvent, JsonFormat.Compact);
        lock (_gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            using var stream = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read);
            using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            writer.WriteLine(line);
        }

        TryProtect();
    }

    public IReadOnlyList<AuditEvent> ReadAll()
    {
        if (!File.Exists(_path))
        {
            return Array.Empty<AuditEvent>();
        }

        string[] lines;
        lock (_gate)
        {
            using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            lines = reader.ReadToEnd().Split('\n');
        }

        var events = new List<AuditEvent>();
        foreach (var raw in lines)
        {
            var line = raw.Trim().TrimEnd('\r');
            if (line.Length == 0 || line.Length > 1_000_000)
            {
                continue;
            }

            try
            {
                var parsed = JsonSerializer.Deserialize<AuditEvent>(line, JsonFormat.Compact);
                if (parsed is not null)
                {
                    events.Add(parsed);
                }
            }
            catch (JsonException)
            {
                // Keep the rest of the log readable if one line is corrupt.
            }
        }

        return events;
    }

    private void TryProtect()
    {
        try
        {
            _protector.ProtectFile(_path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // The log line is already durable. A later write retries protection.
        }
    }
}

public static class CsvExporter
{
    public static readonly string[] Headers =
    [
        "timestamp",
        "user",
        "machine",
        "action",
        "actionKo",
        "vendorId",
        "productId",
        "serialNumber",
        "deviceName",
        "instanceId",
        "policyMode",
        "result",
        "detail"
    ];

    public static string Export(IReadOnlyList<AuditEvent> events)
    {
        var builder = new StringBuilder();
        builder.Append('\uFEFF');
        builder.AppendLine(string.Join(',', Headers));
        foreach (var auditEvent in events)
        {
            builder.Append(Cell(auditEvent.Timestamp.ToString("O")));
            builder.Append(',');
            builder.Append(Cell(auditEvent.UserName));
            builder.Append(',');
            builder.Append(Cell(auditEvent.MachineName));
            builder.Append(',');
            builder.Append(Cell(auditEvent.Action.ToString()));
            builder.Append(',');
            builder.Append(Cell(auditEvent.Action.ToKorean()));
            builder.Append(',');
            builder.Append(Cell(auditEvent.VendorId));
            builder.Append(',');
            builder.Append(Cell(auditEvent.ProductId));
            builder.Append(',');
            builder.Append(Cell(auditEvent.SerialNumber));
            builder.Append(',');
            builder.Append(Cell(auditEvent.DeviceName));
            builder.Append(',');
            builder.Append(Cell(auditEvent.InstanceId));
            builder.Append(',');
            builder.Append(Cell(auditEvent.PolicyMode));
            builder.Append(',');
            builder.Append(Cell(auditEvent.Result));
            builder.Append(',');
            builder.Append(Cell(auditEvent.Detail));
            builder.Append('\n');
        }

        return builder.ToString();
    }

    public static string Cell(string? value)
    {
        var text = value ?? "";
        if (text.Length > 0 && "=+-@\t\r".Contains(text[0]))
        {
            text = "'" + text;
        }

        if (text.Contains('"') || text.Contains(',') || text.Contains('\n') || text.Contains('\r'))
        {
            return "\"" + text.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        }

        return text;
    }
}
