using System.Management;
using System.Runtime.InteropServices;
using UsbAccessControl.Core;

namespace UsbAccessControl.Windows;

public sealed class WmiDeviceWakeSignal : IDeviceWakeSignal
{
    private readonly List<ManagementEventWatcher> _watchers = new();

    public event EventHandler? Signaled;

    public void Start()
    {
        Exception? last = null;
        var started = 0;
        foreach (var query in new[] { "SELECT * FROM Win32_DeviceChangeEvent", "SELECT * FROM Win32_VolumeChangeEvent" })
        {
            try
            {
                var watcher = new ManagementEventWatcher(new WqlEventQuery(query));
                watcher.EventArrived += OnEvent;
                watcher.Start();
                _watchers.Add(watcher);
                started++;
            }
            catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or PlatformNotSupportedException or COMException or InvalidOperationException)
            {
                last = ex;
            }
        }

        if (started == 0)
        {
            throw new DeviceControlException(
                "WMI 장치 이벤트를 구독하지 못했습니다. 주기적 검색은 계속할 수 있습니다. " + last?.Message);
        }
    }

    public void Dispose()
    {
        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.Stop();
            }
            catch (ManagementException)
            {
                // The subscription is already gone.
            }

            watcher.Dispose();
        }

        _watchers.Clear();
    }

    private void OnEvent(object sender, EventArrivedEventArgs e) => Signaled?.Invoke(this, EventArgs.Empty);
}
