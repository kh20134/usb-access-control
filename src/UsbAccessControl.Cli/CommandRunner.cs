using System.Text.Json;
using UsbAccessControl.Core;
using UsbAccessControl.Hosting;

namespace UsbAccessControl.Cli;

public interface IConsoleEnvironment
{
    string? GetVariable(string name);
    bool IsInputRedirected { get; }
    string? ReadSecret(string prompt);
}

public sealed class SystemConsoleEnvironment : IConsoleEnvironment
{
    public string? GetVariable(string name) => Environment.GetEnvironmentVariable(name);
    public bool IsInputRedirected => Console.IsInputRedirected;

    public string? ReadSecret(string prompt)
    {
        Console.Error.Write(prompt);
        var characters = new List<char>();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (characters.Count > 0)
                {
                    characters.RemoveAt(characters.Count - 1);
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                characters.Add(key.KeyChar);
            }
        }

        return new string(characters.ToArray());
    }
}

public sealed class ArgumentSet
{
    public ArgumentSet(IReadOnlyList<string> positionals, IReadOnlyDictionary<string, string> options)
    {
        Positionals = positionals;
        Options = options;
    }

    public IReadOnlyList<string> Positionals { get; }
    public IReadOnlyDictionary<string, string> Options { get; }

    public bool Flag(string name) =>
        Options.TryGetValue(name, out var value) && value.Equals("true", StringComparison.OrdinalIgnoreCase);

    public string? Option(string name) => Options.TryGetValue(name, out var value) && value != "true" ? value : null;
}

public static class ArgTokenizer
{
    public static ArgumentSet Tokenize(IReadOnlyList<string> args)
    {
        var positionals = new List<string>();
        var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Count; index++)
        {
            var token = args[index];
            if (!token.StartsWith("--", StringComparison.Ordinal) || token.Length < 3)
            {
                positionals.Add(token);
                continue;
            }

            var body = token[2..];
            var equals = body.IndexOf('=');
            if (equals >= 0)
            {
                options[body[..equals]] = body[(equals + 1)..];
                continue;
            }

            if (index + 1 < args.Count && !args[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                options[body] = args[++index];
            }
            else
            {
                options[body] = "true";
            }
        }

        return new ArgumentSet(positionals, options);
    }
}

public sealed class CommandRunner
{
    private readonly IConsoleEnvironment _environment;
    private readonly Func<string?, PolicySession> _createSession;
    private readonly Action<string>? _installTask;
    private readonly Action? _uninstallTask;

    public CommandRunner(
        IConsoleEnvironment environment,
        Func<string?, PolicySession> createSession,
        Action<string>? installTask = null,
        Action? uninstallTask = null)
    {
        _environment = environment;
        _createSession = createSession;
        _installTask = installTask;
        _uninstallTask = uninstallTask;
    }

    public static CommandRunner CreateDefault() => new(
        new SystemConsoleEnvironment(),
        HostFactory.CreateProduction,
        HostFactory.InstallStartupTask,
        HostFactory.UninstallStartupTask);

    public int Run(IReadOnlyList<string> args, TextWriter stdout, TextWriter stderr)
    {
        try
        {
            return RunCore(args, stdout, stderr);
        }
        catch (AuthorizationException ex)
        {
            stderr.WriteLine(ex.Message);
            return 2;
        }
        catch (ValidationException ex)
        {
            stderr.WriteLine(ex.Message);
            return 3;
        }
        catch (PlatformNotSupportedException ex)
        {
            stderr.WriteLine(ex.Message);
            return 4;
        }
        catch (UsbAccessControlException ex)
        {
            stderr.WriteLine(ex.Message);
            return 1;
        }
        catch (UnauthorizedAccessException ex)
        {
            stderr.WriteLine(ex.Message);
            return 4;
        }
    }

    private int RunCore(IReadOnlyList<string> args, TextWriter stdout, TextWriter stderr)
    {
        var parsed = ArgTokenizer.Tokenize(args);
        var help = parsed.Flag("help") || (parsed.Positionals.Count > 0 && parsed.Positionals[0] == "help");
        if (parsed.Positionals.Count == 0 || help)
        {
            stdout.WriteLine(HelpText);
            return help ? 0 : 3;
        }

        var command = parsed.Positionals[0];
        var sub = parsed.Positionals.Count > 1 ? parsed.Positionals[1] : "";
        if (command is "task")
        {
            return RunTask(sub, stdout, stderr);
        }

        var session = _createSession(parsed.Option("data-dir"));
        var password = ResolvePassword(parsed);
        if (NeedsPassword(session, command, sub) && string.IsNullOrEmpty(password))
        {
            if (_environment.IsInputRedirected)
            {
                stderr.WriteLine("관리자 암호가 필요합니다. --password 또는 환경 변수 USBAC_ADMIN_PASSWORD를 사용하세요. 프로세스 목록에 암호가 보이지 않게 하려면 환경 변수를 쓰세요.");
                return 2;
            }

            password = _environment.ReadSecret("관리자 암호: ");
        }

        return (command, sub) switch
        {
            ("policy", "show") => ShowPolicy(session, parsed.Flag("json"), stdout),
            ("policy", "set") => SetPolicy(session, parsed, password, stdout, stderr),
            ("policy", "apply") => ApplyPolicy(session, parsed, password, stdout, stderr),
            ("whitelist", "list") => ListWhitelist(session, parsed.Flag("json"), stdout),
            ("whitelist", "add") => AddWhitelist(session, parsed, password, stdout),
            ("whitelist", "remove") => RemoveWhitelist(session, parsed, password, stdout, stderr),
            ("devices", _) => ShowDevices(session, parsed.Flag("json"), stdout),
            ("logs", "export") => ExportLogs(session, parsed, stdout, stderr),
            ("logs", _) => ShowLogs(session, parsed, parsed.Flag("json"), stdout),
            ("password", "set") => SetPassword(session, parsed, password, stdout, stderr),
            ("password", "clear") => ClearPassword(session, password, stdout),
            ("monitor", _) => RunMonitor(session),
            _ => Unknown(stdout)
        };
    }

    private int RunTask(string sub, TextWriter stdout, TextWriter stderr)
    {
        if (!OperatingSystem.IsWindows() || _installTask is null || _uninstallTask is null)
        {
            stderr.WriteLine("작업 스케줄러 등록은 Windows에서만 가능합니다.");
            return 4;
        }

        var exe = Environment.ProcessPath;
        if (sub == "install")
        {
            if (string.IsNullOrEmpty(exe))
            {
                stderr.WriteLine("실행 파일 경로를 찾지 못했습니다.");
                return 1;
            }

            _installTask(exe);
            stdout.WriteLine($"시작 작업 '{ScheduledTaskDefinition.TaskName}'을 등록했습니다. SYSTEM 권한으로 monitor가 실행됩니다.");
            return 0;
        }

        if (sub == "uninstall")
        {
            _uninstallTask();
            stdout.WriteLine($"시작 작업 '{ScheduledTaskDefinition.TaskName}'을 제거했습니다.");
            return 0;
        }

        stderr.WriteLine("사용법: usbac task install | usbac task uninstall");
        return 3;
    }

    private static int ShowPolicy(PolicySession session, bool json, TextWriter stdout)
    {
        var plan = session.Preview();
        if (json)
        {
            stdout.WriteLine(JsonSerializer.Serialize(PolicyProjection.From(session, plan), JsonFormat.Indented));
            return 0;
        }

        stdout.WriteLine(PolicyStatusText.Build(session.Document, plan));
        stdout.WriteLine("데이터 폴더의 policy.json이 원하는 상태이고, '적용됨'은 마지막 적용 시점의 지문과 같을 때입니다.");
        foreach (var note in plan.Notes)
        {
            stdout.WriteLine("- " + note);
        }

        var drift = session.ReadRegistryDrift();
        if (drift.Count > 0)
        {
            stdout.WriteLine(drift.All(item => item.Matches)
                ? "레지스트리 값이 원하는 정책과 같습니다."
                : "레지스트리 값이 원하는 정책과 다릅니다. policy apply로 다시 적용하세요. 도메인 그룹 정책이 덮어썼을 수 있습니다.");
        }

        if (session.LoadWarnings.Count > 0)
        {
            foreach (var warning in session.LoadWarnings)
            {
                stdout.WriteLine(warning);
            }
        }

        return 0;
    }

    private static int SetPolicy(PolicySession session, ArgumentSet args, string? password, TextWriter stdout, TextWriter stderr)
    {
        if (args.Positionals.Count < 3 || !PolicyModeNames.TryParse(args.Positionals[2], out var mode))
        {
            stderr.WriteLine("사용법: usbac policy set <block|readonly|allow>");
            return 3;
        }

        session.SetMode(mode, password);
        stdout.WriteLine($"{mode.ToKorean()}으로 저장했습니다. Windows에 반영하려면 usbac policy apply를 실행하세요.");
        return 0;
    }

    private static int ApplyPolicy(PolicySession session, ArgumentSet args, string? password, TextWriter stdout, TextWriter stderr)
    {
        if (session.Document.Mode == PolicyMode.Block && !args.Flag("yes"))
        {
            stderr.WriteLine("차단 정책을 적용하려면 --yes 를 함께 지정하세요. 화이트리스트가 없으면 USB 저장장치와 이동식 저장 클래스 전체가 차단됩니다.");
            return 3;
        }

        var result = session.Apply(password);
        stdout.WriteLine(PolicyStatusText.Build(session.Document, result.Plan));
        foreach (var warning in result.Warnings)
        {
            stdout.WriteLine(warning);
        }

        return result.Warnings.Count == 0 ? 0 : 1;
    }

    private static int ListWhitelist(PolicySession session, bool json, TextWriter stdout)
    {
        if (json)
        {
            stdout.WriteLine(JsonSerializer.Serialize(session.Document.Whitelist.Select(WhitelistProjection.From), JsonFormat.Indented));
            return 0;
        }

        if (session.Document.Whitelist.Count == 0)
        {
            stdout.WriteLine("화이트리스트가 비어 있습니다.");
            return 0;
        }

        foreach (var entry in session.Document.Whitelist)
        {
            stdout.WriteLine($"{entry.Id:D}\t{entry.VendorId}:{entry.ProductId}\t{entry.SerialNumber ?? "*"}\t{entry.DisplayName}");
        }

        return 0;
    }

    private static int AddWhitelist(PolicySession session, ArgumentSet args, string? password, TextWriter stdout)
    {
        var entry = session.AddWhitelist(
            args.Option("vid") ?? "",
            args.Option("pid") ?? "",
            args.Option("serial"),
            args.Option("name") ?? "",
            args.Option("note"),
            password);
        stdout.WriteLine($"{entry.Id:D} 항목을 저장했습니다. Windows에 반영하려면 usbac policy apply를 실행하세요.");
        return 0;
    }

    private static int RemoveWhitelist(PolicySession session, ArgumentSet args, string? password, TextWriter stdout, TextWriter stderr)
    {
        if (!Guid.TryParse(args.Option("id"), out var id))
        {
            stderr.WriteLine("사용법: usbac whitelist remove --id <guid>");
            return 3;
        }

        stdout.WriteLine(session.RemoveWhitelist(id, password)
            ? "항목을 삭제했습니다. Windows에 반영하려면 usbac policy apply를 실행하세요."
            : "해당 항목이 없습니다.");
        return 0;
    }

    private static int ShowDevices(PolicySession session, bool json, TextWriter stdout)
    {
        var devices = session.ListDevices()
            .Where(device => device.IsMassStorage && DeviceIdParser.IsUsbStorInstance(device.InstanceId))
            .Select(device => new DeviceProjection(device, session.Explain(device)))
            .ToArray();
        if (json)
        {
            stdout.WriteLine(JsonSerializer.Serialize(devices, JsonFormat.Indented));
            return 0;
        }

        if (devices.Length == 0)
        {
            stdout.WriteLine("연결된 USB 저장장치가 없습니다.");
            return 0;
        }

        foreach (var device in devices)
        {
            stdout.WriteLine($"{device.AccessKo}\t{device.VendorId}:{device.ProductId}\t{device.SerialNumber}\t{device.Name}\t{device.InstanceId}");
        }

        return 0;
    }

    private static int ShowLogs(PolicySession session, ArgumentSet args, bool json, TextWriter stdout)
    {
        var limit = 20;
        if (args.Option("limit") is { } text)
        {
            if (!int.TryParse(text, out limit) || limit < 1)
            {
                stdout.WriteLine("사용법: usbac logs --limit 20");
                return 3;
            }
        }

        var events = session.RecentLogs(limit);
        if (json)
        {
            stdout.WriteLine(JsonSerializer.Serialize(events, JsonFormat.Indented));
            return 0;
        }

        foreach (var auditEvent in events)
        {
            stdout.WriteLine($"{auditEvent.Timestamp:yyyy-MM-dd HH:mm:ss}Z\t{auditEvent.UserName}\t{auditEvent.Action.ToKorean()}\t{auditEvent.DeviceName}\t{auditEvent.Result}\t{auditEvent.Detail}");
        }

        return 0;
    }

    private static int ExportLogs(PolicySession session, ArgumentSet args, TextWriter stdout, TextWriter stderr)
    {
        var path = args.Option("out");
        if (string.IsNullOrWhiteSpace(path))
        {
            stderr.WriteLine("사용법: usbac logs export --out audit.csv");
            return 3;
        }

        session.ExportLogs(path);
        stdout.WriteLine(path);
        return 0;
    }

    private static int SetPassword(PolicySession session, ArgumentSet args, string? password, TextWriter stdout, TextWriter stderr)
    {
        var next = args.Option("new");
        if (string.IsNullOrEmpty(next))
        {
            stderr.WriteLine("사용법: usbac password set --new <8자 이상> [--password <현재 암호>]");
            return 3;
        }

        session.SetAdminPassword(password, next);
        stdout.WriteLine("관리자 암호를 저장했습니다. 암호는 PBKDF2 해시로만 기록됩니다.");
        return 0;
    }

    private static int ClearPassword(PolicySession session, string? password, TextWriter stdout)
    {
        session.ClearAdminPassword(password);
        stdout.WriteLine("관리자 암호를 해제했습니다. 이후 변경은 관리자 권한만으로 가능합니다.");
        return 0;
    }

    private static int RunMonitor(PolicySession session)
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cts.Cancel();
        };
        using var wake = HostFactory.CreateWakeSignal();
        MonitoringLoop.RunAsync(session, wake, Console.Out, cts.Token).GetAwaiter().GetResult();
        return 0;
    }

    private static int Unknown(TextWriter stdout)
    {
        stdout.WriteLine(HelpText);
        return 3;
    }

    private string? ResolvePassword(ArgumentSet args)
    {
        if (args.Option("password") is { } password)
        {
            return password;
        }

        var fromEnv = _environment.GetVariable("USBAC_ADMIN_PASSWORD");
        return string.IsNullOrEmpty(fromEnv) ? null : fromEnv;
    }

    private static bool NeedsPassword(PolicySession session, string command, string sub)
    {
        if (session.Document.AdminPassword is null)
        {
            return false;
        }

        return (command, sub) is ("policy", "set") or ("policy", "apply") or ("whitelist", "add") or ("whitelist", "remove")
            or ("password", "set") or ("password", "clear");
    }

    public const string HelpText =
        """
        usbac — USB 저장장치 접근통제

        정책
          usbac policy show [--json]
          usbac policy set <block|readonly|allow> [--password <암호>]
          usbac policy apply [--yes] [--password <암호>]

        화이트리스트 (VID/PID 필수, 일련번호 생략 시 해당 제품 전체)
          usbac whitelist list [--json]
          usbac whitelist add --vid 0781 --pid 5581 [--serial <일련번호>] --name <이름> [--note <메모>]
          usbac whitelist remove --id <guid>

        장치, 로그, 암호, 감시
          usbac devices [--json]
          usbac logs [--limit 20] [--json]
          usbac logs export --out audit.csv
          usbac password set --new <8자 이상>
          usbac password clear
          usbac monitor
          usbac task install
          usbac task uninstall

        공통
          --data-dir <폴더>   기본값: Windows는 %ProgramData%\UsbAccessControl
          --password <암호>   또는 환경 변수 USBAC_ADMIN_PASSWORD
          차단 적용에는 --yes 가 필요합니다.

        종료 코드: 0 성공, 2 암호 거부, 3 사용법, 4 권한 또는 운영 체제, 1 그 외 실패
        """;
}

public sealed record PolicyProjection(
    string Mode,
    string ModeKo,
    bool PasswordRequired,
    bool Applied,
    string Status,
    IReadOnlyList<string> Notes,
    IReadOnlyList<WhitelistProjection> Whitelist)
{
    public static PolicyProjection From(PolicySession session, EnforcementPlan plan) => new(
        plan.Mode.ToString(),
        plan.Mode.ToKorean(),
        session.Document.AdminPassword is not null,
        session.Document.IsApplied,
        PolicyStatusText.Build(session.Document, plan),
        plan.Notes,
        session.Document.Whitelist.Select(WhitelistProjection.From).ToArray());
}

public sealed record WhitelistProjection(Guid Id, string VendorId, string ProductId, string? SerialNumber, string DisplayName, string? Note)
{
    public static WhitelistProjection From(WhitelistEntry entry) =>
        new(entry.Id, entry.VendorId, entry.ProductId, entry.SerialNumber, entry.DisplayName, entry.Note);
}

public sealed record DeviceProjection(string InstanceId, string? VendorId, string? ProductId, string? SerialNumber, string? Name, string Access, string AccessKo)
{
    public DeviceProjection(UsbStorageDevice device, EffectiveAccess access) : this(
        device.InstanceId,
        device.VendorId,
        device.ProductId,
        device.SerialNumber,
        device.FriendlyName,
        access.ToString(),
        access.ToKorean())
    {
    }
}
