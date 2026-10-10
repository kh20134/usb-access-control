using UsbAccessControl.Core;

namespace UsbAccessControl.Hosting;

public static class MonitoringLoop
{
    public static async Task RunAsync(
        PolicySession session,
        IDeviceWakeSignal wake,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        using var ping = new SemaphoreSlim(0, 1);
        void OnWake(object? sender, EventArgs args)
        {
            try
            {
                ping.Release();
            }
            catch (SemaphoreFullException)
            {
                // A scan is already queued.
            }
        }

        wake.Signaled += OnWake;
        try
        {
            try
            {
                wake.Start();
            }
            catch (Exception ex) when (ex is DeviceControlException or PlatformNotSupportedException or UnauthorizedAccessException)
            {
                output.WriteLine(ex.Message);
            }

            session.MarkMonitor(started: true);
            output.WriteLine("USB 저장장치 감시를 시작했습니다. 종료하려면 Ctrl+C 를 누르세요.");
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var scan = session.ScanAndEnforce();
                    foreach (var warning in scan.Warnings)
                    {
                        output.WriteLine(warning);
                    }
                }
                catch (Exception ex) when (ex is DeviceControlException or IOException or UnauthorizedAccessException or PlatformNotSupportedException)
                {
                    output.WriteLine(ex.Message);
                }

                var delay = Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
                var signaled = ping.WaitAsync(cancellationToken);
                await Task.WhenAny(delay, signaled);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        finally
        {
            wake.Signaled -= OnWake;
            session.MarkMonitor(started: false);
        }
    }
}
