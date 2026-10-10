using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using UsbAccessControl.Hosting;

namespace UsbAccessControl.App;

public partial class MainWindow : Window
{
    private CancellationTokenSource? _monitor;

    public MainWindow()
    {
        InitializeComponent();
        Opened += OnOpened;
        Closing += OnClosing;
    }

    private MainViewModel? Model => DataContext as MainViewModel;

    private async void OnOpened(object? sender, EventArgs e)
    {
        if (Model is { IsPreview: false } && OperatingSystem.IsWindows())
        {
            await StartMonitorAsync();
        }
    }

    private void OnClosing(object? sender, WindowClosingEventArgs e) => StopMonitor();

    private void OnApply(object? sender, RoutedEventArgs e) => Model?.Apply();

    private void OnRefresh(object? sender, RoutedEventArgs e) => Model?.ScanOnce();

    private void OnAdd(object? sender, RoutedEventArgs e) => Model?.AddWhitelist();

    private void OnRemove(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: WhitelistRow row })
        {
            Model?.RemoveWhitelist(row.Id);
        }
    }

    private void OnStage(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: DeviceRow row })
        {
            Model?.StageFromDevice(row);
        }
    }

    private void OnSetPassword(object? sender, RoutedEventArgs e) => Model?.SetPassword();

    private void OnClearPassword(object? sender, RoutedEventArgs e) => Model?.ClearPassword();

    private async void OnExport(object? sender, RoutedEventArgs e)
    {
        if (Model is null)
        {
            return;
        }

        var storage = TopLevel.GetTopLevel(this)?.StorageProvider;
        if (storage is null)
        {
            return;
        }

        var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "감사 로그 내보내기",
            DefaultExtension = "csv",
            SuggestedFileName = "usb-audit.csv",
            FileTypeChoices = [new FilePickerFileType("CSV") { Patterns = ["*.csv"] }]
        });
        var path = file?.TryGetLocalPath();
        if (!string.IsNullOrWhiteSpace(path))
        {
            Model.ExportLogs(path);
        }
    }

    private async void OnMonitor(object? sender, RoutedEventArgs e)
    {
        if (_monitor is null)
        {
            await StartMonitorAsync();
        }
        else
        {
            StopMonitor();
        }
    }

    private async Task StartMonitorAsync()
    {
        if (Model is null || _monitor is not null)
        {
            return;
        }

        _monitor = new CancellationTokenSource();
        Model.MonitorText = "감시 중";
        var token = _monitor.Token;
        try
        {
            while (!token.IsCancellationRequested)
            {
                Model.ScanOnce();
                await Task.Delay(TimeSpan.FromSeconds(2), token);
            }
        }
        catch (OperationCanceledException)
        {
            // The window is closing or the operator stopped the watch.
        }
    }

    private void StopMonitor()
    {
        if (_monitor is null)
        {
            return;
        }

        _monitor.Cancel();
        _monitor.Dispose();
        _monitor = null;
        if (Model is not null)
        {
            Model.MonitorText = "감시 중지";
        }
    }
}
