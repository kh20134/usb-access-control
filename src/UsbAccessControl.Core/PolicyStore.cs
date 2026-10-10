using System.Text;
using System.Text.Json;

namespace UsbAccessControl.Core;

public interface IFileProtector
{
    void ProtectDirectory(string directory);
    void ProtectFile(string path);
}

public sealed class PortableFileProtector : IFileProtector
{
    public void ProtectDirectory(string directory)
    {
        if (!OperatingSystem.IsWindows() && Directory.Exists(directory))
        {
            File.SetUnixFileMode(
                directory,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    public void ProtectFile(string path)
    {
        if (!OperatingSystem.IsWindows() && File.Exists(path))
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}

public sealed class PolicyLoadResult
{
    public required PolicyDocument Document { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
}

public sealed class PolicyStore
{
    private readonly string _path;
    private readonly IFileProtector _protector;

    public PolicyStore(string directory, IFileProtector protector)
    {
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "policy.json");
        _protector = protector;
    }

    public string PathToFile => _path;

    public PolicyLoadResult LoadOrCreate()
    {
        if (!File.Exists(_path))
        {
            return new PolicyLoadResult
            {
                Document = new PolicyDocument(),
                Warnings = Array.Empty<string>()
            };
        }

        PolicyDocument? document;
        try
        {
            var json = File.ReadAllText(_path, Encoding.UTF8);
            document = JsonSerializer.Deserialize<PolicyDocument>(json, JsonFormat.Indented);
        }
        catch (JsonException ex)
        {
            throw new ValidationException("정책 파일을 읽지 못했습니다. Windows 설정은 바꾸지 않았습니다. " + ex.Message);
        }

        if (document is null)
        {
            throw new ValidationException("정책 파일이 비어 있습니다. Windows 설정은 바꾸지 않았습니다.");
        }

        if (document.Version > PolicyDocument.CurrentVersion)
        {
            throw new ValidationException(
                $"정책 파일 버전 {document.Version}은 이 프로그램({PolicyDocument.CurrentVersion})에서 지원하지 않습니다. Windows 설정은 바꾸지 않았습니다.");
        }

        document.Version = PolicyDocument.CurrentVersion;
        var warnings = new List<string>();
        var kept = new List<WhitelistEntry>();
        foreach (var entry in document.Whitelist)
        {
            try
            {
                kept.Add(WhitelistRules.Create(
                    entry.VendorId,
                    entry.ProductId,
                    entry.SerialNumber,
                    entry.DisplayName,
                    entry.Note,
                    entry.CreatedAt,
                    entry.Id == Guid.Empty ? Guid.NewGuid() : entry.Id));
            }
            catch (ValidationException ex)
            {
                warnings.Add($"화이트리스트 항목을 무시했습니다. 해당 장치는 허용되지 않습니다. {ex.Message}");
            }
        }

        document.Whitelist = kept;
        return new PolicyLoadResult { Document = document, Warnings = warnings };
    }

    public void Save(PolicyDocument document)
    {
        var json = JsonSerializer.Serialize(document, JsonFormat.Indented);
        var temp = _path + ".tmp";
        File.WriteAllText(temp, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.Move(temp, _path, overwrite: true);
        _protector.ProtectFile(_path);
    }
}

public sealed class EnforcementState
{
    public List<string> DisabledInstanceIds { get; set; } = new();
}

public sealed class EnforcementStateStore
{
    private readonly string _path;
    private readonly IFileProtector _protector;

    public EnforcementStateStore(string directory, IFileProtector protector)
    {
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "enforcement-state.json");
        _protector = protector;
    }

    public EnforcementState Load()
    {
        if (!File.Exists(_path))
        {
            return new EnforcementState();
        }

        try
        {
            var json = File.ReadAllText(_path, Encoding.UTF8);
            return JsonSerializer.Deserialize<EnforcementState>(json, JsonFormat.Indented) ?? new EnforcementState();
        }
        catch (JsonException)
        {
            return new EnforcementState();
        }
    }

    public void Save(EnforcementState state)
    {
        var json = JsonSerializer.Serialize(state, JsonFormat.Indented);
        var temp = _path + ".tmp";
        File.WriteAllText(temp, json, new UTF8Encoding(false));
        File.Move(temp, _path, overwrite: true);
        _protector.ProtectFile(_path);
    }
}

public static class AppPaths
{
    public const string FolderName = "UsbAccessControl";

    public static string ResolveDataDirectory(string? overridePath)
    {
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            return Path.GetFullPath(overridePath);
        }

        if (OperatingSystem.IsWindows())
        {
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.Combine(programData, FolderName);
        }

        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(local))
        {
            local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        }

        return Path.Combine(local, FolderName);
    }
}

public static class ScheduledTaskDefinition
{
    public const string TaskName = "UsbAccessControlMonitor";

    public static IReadOnlyList<string> InstallArguments(string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath) || !Path.IsPathRooted(exePath) || exePath.Contains('"'))
        {
            throw new ValidationException("예약 작업에 넣을 실행 파일 경로는 따옴표 없는 절대 경로여야 합니다.");
        }

        return
        [
            "/Create",
            "/TN",
            TaskName,
            "/SC",
            "ONSTART",
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
            "/F",
            "/TR",
            $"\"{exePath}\" monitor"
        ];
    }

    public static IReadOnlyList<string> UninstallArguments() =>
    [
        "/Delete",
        "/TN",
        TaskName,
        "/F"
    ];
}
