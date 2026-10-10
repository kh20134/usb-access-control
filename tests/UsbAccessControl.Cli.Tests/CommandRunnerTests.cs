using UsbAccessControl.Cli;
using UsbAccessControl.Core;

namespace UsbAccessControl.Cli.Tests;

public class CommandRunnerTests
{
    [Fact]
    public void Help_and_policy_roundtrip_do_not_apply_block_without_confirmation()
    {
        using var fixture = new Fixture();
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        Assert.Equal(3, fixture.Runner.Run([], stdout, stderr));
        Assert.Contains("usbac", stdout.ToString());
        Assert.Equal(0, fixture.Runner.Run(["--help"], new StringWriter(), stderr));

        stdout.GetStringBuilder().Clear();
        Assert.Equal(0, fixture.Runner.Run(["policy", "set", "readonly", "--data-dir", fixture.DataDir], stdout, stderr));
        Assert.Equal(0, fixture.Runner.Run(["policy", "set", "block", "--data-dir", fixture.DataDir], stdout, stderr));
        Assert.Equal(3, fixture.Runner.Run(["policy", "apply", "--data-dir", fixture.DataDir], stdout, stderr));
        Assert.Contains("--yes", stderr.ToString());

        var show = new StringWriter();
        Assert.Equal(0, fixture.Runner.Run(["policy", "show", "--data-dir", fixture.DataDir], show, stderr));
        Assert.Contains("차단", show.ToString());
        Assert.Contains("아직 이 PC에 적용되지 않음", show.ToString());

        Assert.Equal(0, fixture.Runner.Run(["policy", "apply", "--yes", "--data-dir", fixture.DataDir], show, stderr));
        Assert.Equal(0, fixture.Runner.Run(["whitelist", "add", "--vid", "0781", "--pid", "5581", "--serial", "ABC", "--name", "SanDisk", "--data-dir", fixture.DataDir], show, stderr));
        var list = new StringWriter();
        Assert.Equal(0, fixture.Runner.Run(["whitelist", "list", "--json", "--data-dir", fixture.DataDir], list, stderr));
        Assert.Contains("0781", list.ToString());
        Assert.Contains("SanDisk", list.ToString());
    }

    [Fact]
    public void Password_and_csv_export()
    {
        using var fixture = new Fixture();
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        Assert.Equal(0, fixture.Runner.Run(["password", "set", "--new", "correct-password", "--data-dir", fixture.DataDir], stdout, stderr));
        Assert.Equal(2, fixture.Runner.Run(["policy", "set", "allow", "--password", "wrong-password", "--data-dir", fixture.DataDir], stdout, stderr));
        Assert.Equal(0, fixture.Runner.Run(["policy", "set", "allow", "--password", "correct-password", "--data-dir", fixture.DataDir], stdout, stderr));

        var csv = Path.Combine(fixture.DataDir, "out.csv");
        Assert.Equal(0, fixture.Runner.Run(["logs", "export", "--out", csv, "--data-dir", fixture.DataDir], stdout, stderr));
        Assert.True(File.Exists(csv));
        Assert.Contains("passwordSet", File.ReadAllText(csv), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Task_install_is_refused_off_windows()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var fixture = new Fixture();
        var stderr = new StringWriter();
        Assert.Equal(4, fixture.Runner.Run(["task", "install"], new StringWriter(), stderr));
        Assert.Contains("Windows", stderr.ToString());
    }

    private sealed class Fixture : IDisposable
    {
        public Fixture()
        {
            DataDir = Path.Combine(Path.GetTempPath(), "usbac-cli", Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(DataDir);
            Runner = new CommandRunner(new RedirectedEnvironment(), dataDir =>
            {
                var path = string.IsNullOrWhiteSpace(dataDir) ? DataDir : dataDir;
                var protector = new PortableFileProtector();
                Directory.CreateDirectory(path);
                return new PolicySession(
                    new PolicyStore(path, protector),
                    new AuditLog(path, protector),
                    new EnforcementStateStore(path, protector),
                    new EnvironmentUserContext(),
                    TimeProvider.System,
                    new RecordingPolicyEnforcer(),
                    new EmptyDeviceEnumerator(),
                    new RecordingDeviceController(),
                    new FixedElevation(true),
                    SessionOptions.Tests);
            });
        }

        public string DataDir { get; }
        public CommandRunner Runner { get; }

        public void Dispose()
        {
            try
            {
                System.IO.Directory.Delete(DataDir, recursive: true);
            }
            catch (IOException)
            {
                // Temporary files can remain.
            }
        }
    }

    private sealed class RedirectedEnvironment : IConsoleEnvironment
    {
        public string? GetVariable(string name) => null;
        public bool IsInputRedirected => true;
        public string? ReadSecret(string prompt) => null;
    }
}
