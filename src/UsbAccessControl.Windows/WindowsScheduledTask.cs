using System.Diagnostics;
using UsbAccessControl.Core;

namespace UsbAccessControl.Windows;

public static class WindowsScheduledTask
{
    public static void Install(string exePath) => Run(ScheduledTaskDefinition.InstallArguments(exePath));

    public static void Uninstall() => Run(ScheduledTaskDefinition.UninstallArguments());

    private static void Run(IReadOnlyList<string> arguments)
    {
        var start = new ProcessStartInfo("schtasks.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ?? throw new PolicyApplyException("schtasks.exe를 시작하지 못했습니다.");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            var detail = string.Join(" ", new[] { stderr, stdout }.Where(text => !string.IsNullOrWhiteSpace(text))).Trim();
            throw new PolicyApplyException($"작업 스케줄러 명령이 실패했습니다 ({process.ExitCode}). {detail}");
        }
    }
}
