using Avalonia;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Media;
using UsbAccessControl.App;
using Xunit;

[assembly: AvaloniaTestApplication(typeof(UsbAccessControl.App.Tests.HeadlessAppBuilder))]

namespace UsbAccessControl.App.Tests;

public class HeadlessAppBuilder
{
    public static AppBuilder BuildAvaloniaApp()
    {
        Environment.SetEnvironmentVariable("USBAC_HEADLESS", "1");
        var builder = AppBuilder.Configure<App>()
            .UseSkia()
            .WithInterFont()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });
        if (Environment.GetEnvironmentVariable("USBAC_SCREENSHOT_CJK") == "1")
        {
            builder = builder.With(new FontManagerOptions { DefaultFamilyName = "Noto Sans CJK KR" });
        }

        return builder;
    }
}

public class ScreenshotTests
{
    [AvaloniaFact]
    public void MainWindow_renders_a_real_frame()
    {
        var window = new MainWindow
        {
            DataContext = PreviewSession.CreateModel(),
            Width = 1180,
            Height = 820
        };
        window.FontFamily = Environment.GetEnvironmentVariable("USBAC_SCREENSHOT_CJK") == "1"
            ? new FontFamily("Noto Sans CJK KR")
            : FontFamily.Parse("avares://Avalonia.Fonts.Inter/Assets#Inter");
        window.Show();
        var frame = window.CaptureRenderedFrame();
        Assert.NotNull(frame);
        Assert.True(frame!.PixelSize.Width >= 1000);
        Assert.True(frame.PixelSize.Height >= 600);

        var destination = Environment.GetEnvironmentVariable("USBAC_WRITE_SCREENSHOT");
        if (!string.IsNullOrWhiteSpace(destination))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(destination))!);
            frame.Save(destination);
        }
    }

    [Fact]
    public void Preview_model_shows_whitelist_decision()
    {
        var model = PreviewSession.CreateModel();
        Assert.True(model.IsPreview);
        Assert.True(model.IsBlock);
        Assert.Contains(model.Devices, device => device.Name.Contains("SanDisk") && device.Access == "허용");
        Assert.Contains(model.Devices, device => device.Name.Contains("Kingston") && device.Access == "차단");
        Assert.Contains(model.Whitelist, entry => entry.Identity == "0781:5581");
        Assert.Contains("승인된 USB만 허용", model.StatusText);
        Assert.Equal("예시PC · 사용자", model.MachineText);
        Assert.DoesNotContain(Environment.UserName, model.MachineText, StringComparison.Ordinal);
        Assert.NotEmpty(model.Logs);
        Assert.All(model.Logs, row => Assert.Equal("사용자", row.Who));
    }
}
