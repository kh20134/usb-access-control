using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using UsbAccessControl.Core;
using UsbAccessControl.Hosting;

namespace UsbAccessControl.App;

public class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (Environment.GetEnvironmentVariable("USBAC_HEADLESS") != "1"
            && ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var preview = desktop.Args?.Any(arg => arg == "--preview") == true;
            desktop.MainWindow = CreateWindow(preview);
        }

        base.OnFrameworkInitializationCompleted();
    }

    public static MainWindow CreateWindow(bool preview)
    {
        try
        {
            var session = preview ? PreviewSession.Create() : HostFactory.CreateProduction(null);
            return new MainWindow
            {
                DataContext = new MainViewModel(session, preview)
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or UsbAccessControlException or PlatformNotSupportedException)
        {
            return new MainWindow
            {
                DataContext = MainViewModel.Failed(ex.Message)
            };
        }
    }

    }

public static class PreviewSession
{
    public static PolicySession Create()
    {
        var directory = Path.Combine(Path.GetTempPath(), "usbac-preview", Guid.NewGuid().ToString("N"));
        var session = HostFactory.CreatePreview(directory, new PreviewDeviceEnumerator());
        session.AddWhitelist("0781", "5581", "4C530001230101123456", "SanDisk Ultra", "총무팀 승인", null);
        session.SetMode(PolicyMode.Block, null);
        session.Apply(null);
        return session;
    }

    public static MainViewModel CreateModel() => new(Create(), preview: true);
}
