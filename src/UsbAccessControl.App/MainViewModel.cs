using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using UsbAccessControl.Core;
using UsbAccessControl.Hosting;

namespace UsbAccessControl.App;

public sealed class WhitelistRow
{
    public required Guid Id { get; init; }
    public required string Identity { get; init; }
    public required string Serial { get; init; }
    public required string Name { get; init; }
    public required string Note { get; init; }
}

public sealed class DeviceRow
{
    public required string InstanceId { get; init; }
    public required string Name { get; init; }
    public required string Identity { get; init; }
    public required string Serial { get; init; }
    public required string Access { get; init; }
    public string? VendorId { get; init; }
    public string? ProductId { get; init; }
}

public sealed class LogRow
{
    public required string When { get; init; }
    public required string Who { get; init; }
    public required string Action { get; init; }
    public required string Device { get; init; }
    public required string Result { get; init; }
    public required string Detail { get; init; }
}

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly PolicySession _session;
    private bool _suppress;
    private bool _confirmBlock;
    private string _password = "";
    private string _newPassword = "";
    private string _newVid = "";
    private string _newPid = "";
    private string _newSerial = "";
    private string _newName = "";
    private string _newNote = "";
    private string _status = "";
    private string _notes = "";
    private string _error = "";
    private string _monitor = "감시 중지";

    public MainViewModel(PolicySession session, bool preview)
    {
        _session = session;
        IsPreview = preview;
        PreviewBanner = preview
            ? "미리보기 데이터입니다. 장치 목록은 예시이고 Windows 레지스트리는 변경하지 않았습니다."
            : OperatingSystem.IsWindows()
                ? ""
                : "이 운영 체제에서는 정책을 파일로만 저장합니다. 레지스트리 적용은 Windows 10/11 관리자 권한에서 하세요.";
        ElevationText = preview
            ? "미리보기"
            : session.IsElevated
                ? "관리자 권한"
                : OperatingSystem.IsWindows()
                    ? "권한 부족"
                    : "Windows 아님";
        MachineText = $"{Environment.MachineName} · {Environment.UserName}";
        Reload();
    }

    public static MainViewModel Failed(string message)
    {
        var directory = Path.Combine(Path.GetTempPath(), "usbac-error", Guid.NewGuid().ToString("N"));
        var session = HostFactory.CreatePreview(directory, new EmptyDeviceEnumerator());
        var model = new MainViewModel(session, preview: false)
        {
            ErrorMessage = message,
            InputsEnabled = false
        };
        return model;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<WhitelistRow> Whitelist { get; } = new();
    public ObservableCollection<DeviceRow> Devices { get; } = new();
    public ObservableCollection<LogRow> Logs { get; } = new();

    public bool IsPreview { get; }
    public string PreviewBanner { get; }
    public bool ShowPreviewBanner => PreviewBanner.Length > 0;
    public string ElevationText { get; }
    public string MachineText { get; }
    public bool InputsEnabled { get; private set; } = true;

    public string Password
    {
        get => _password;
        set => Set(ref _password, value);
    }

    public string NewPassword
    {
        get => _newPassword;
        set => Set(ref _newPassword, value);
    }

    public string NewVid
    {
        get => _newVid;
        set => Set(ref _newVid, value);
    }

    public string NewPid
    {
        get => _newPid;
        set => Set(ref _newPid, value);
    }

    public string NewSerial
    {
        get => _newSerial;
        set => Set(ref _newSerial, value);
    }

    public string NewName
    {
        get => _newName;
        set => Set(ref _newName, value);
    }

    public string NewNote
    {
        get => _newNote;
        set => Set(ref _newNote, value);
    }

    public string StatusText
    {
        get => _status;
        private set => Set(ref _status, value);
    }

    public string PlanNotes
    {
        get => _notes;
        private set => Set(ref _notes, value);
    }

    public string ErrorMessage
    {
        get => _error;
        set => Set(ref _error, value);
    }

    public string MonitorText
    {
        get => _monitor;
        set => Set(ref _monitor, value);
    }

    public bool IsBlock
    {
        get => _session.Document.Mode == PolicyMode.Block;
        set
        {
            if (value)
            {
                ChangeMode(PolicyMode.Block);
            }
        }
    }

    public bool IsReadOnly
    {
        get => _session.Document.Mode == PolicyMode.ReadOnly;
        set
        {
            if (value)
            {
                ChangeMode(PolicyMode.ReadOnly);
            }
        }
    }

    public bool IsAllow
    {
        get => _session.Document.Mode == PolicyMode.Allow;
        set
        {
            if (value)
            {
                ChangeMode(PolicyMode.Allow);
            }
        }
    }

    public void Reload()
    {
        _suppress = true;
        Notify(nameof(IsBlock));
        Notify(nameof(IsReadOnly));
        Notify(nameof(IsAllow));
        _suppress = false;

        var plan = _session.Preview();
        StatusText = PolicyStatusText.Build(_session.Document, plan);
        PlanNotes = string.Join(Environment.NewLine, plan.Notes);
        if (_session.LoadWarnings.Count > 0 && string.IsNullOrEmpty(ErrorMessage))
        {
            ErrorMessage = string.Join(" ", _session.LoadWarnings);
        }

        Whitelist.Clear();
        foreach (var entry in _session.Document.Whitelist)
        {
            Whitelist.Add(new WhitelistRow
            {
                Id = entry.Id,
                Identity = $"{entry.VendorId}:{entry.ProductId}",
                Serial = entry.SerialNumber ?? "일련번호 무관",
                Name = entry.DisplayName,
                Note = entry.Note ?? ""
            });
        }

        Devices.Clear();
        foreach (var device in _session.ListDevices())
        {
            if (!device.IsMassStorage || !DeviceIdParser.IsUsbStorInstance(device.InstanceId))
            {
                continue;
            }

            var access = _session.Explain(device);
            _session.ControlResults.TryGetValue(device.InstanceId, out var control);
            var label = control is "실패" or "장치 없음" ? control : access.ToKorean();
            Devices.Add(new DeviceRow
            {
                InstanceId = device.InstanceId,
                Name = string.IsNullOrWhiteSpace(device.FriendlyName) ? "이름 없음" : device.FriendlyName,
                Identity = $"{device.VendorId ?? "????"}:{device.ProductId ?? "????"}",
                Serial = device.SerialNumber ?? "-",
                Access = label,
                VendorId = device.VendorId,
                ProductId = device.ProductId
            });
        }

        Logs.Clear();
        foreach (var auditEvent in _session.RecentLogs(8).Reverse())
        {
            Logs.Add(new LogRow
            {
                When = auditEvent.Timestamp.ToLocalTime().ToString("MM-dd HH:mm:ss"),
                Who = auditEvent.UserName,
                Action = auditEvent.Action.ToKorean(),
                Device = auditEvent.DeviceName ?? "",
                Result = auditEvent.Result ?? "",
                Detail = auditEvent.Detail ?? ""
            });
        }
    }

    public void Apply()
    {
        if (!InputsEnabled)
        {
            return;
        }

        try
        {
            if (_session.Document.Mode == PolicyMode.Block && !_confirmBlock)
            {
                _confirmBlock = true;
                ErrorMessage = "";
                StatusText = "차단 정책입니다. 적용 버튼을 한 번 더 누르면 이 PC에 반영됩니다.";
                return;
            }

            _confirmBlock = false;
            var result = _session.Apply(Password);
            ErrorMessage = result.Warnings.Count == 0 ? "" : string.Join(" ", result.Warnings);
            Reload();
        }
        catch (Exception ex) when (ex is UsbAccessControlException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            ErrorMessage = ex.Message;
        }
    }

    public void AddWhitelist()
    {
        if (!InputsEnabled)
        {
            return;
        }

        try
        {
            _session.AddWhitelist(NewVid, NewPid, NewSerial, NewName, NewNote, Password);
            NewVid = "";
            NewPid = "";
            NewSerial = "";
            NewName = "";
            NewNote = "";
            ErrorMessage = "";
            _confirmBlock = false;
            Reload();
        }
        catch (Exception ex) when (ex is UsbAccessControlException or UnauthorizedAccessException)
        {
            ErrorMessage = ex.Message;
        }
    }

    public void RemoveWhitelist(Guid id)
    {
        if (!InputsEnabled)
        {
            return;
        }

        try
        {
            _session.RemoveWhitelist(id, Password);
            ErrorMessage = "";
            _confirmBlock = false;
            Reload();
        }
        catch (Exception ex) when (ex is UsbAccessControlException or UnauthorizedAccessException)
        {
            ErrorMessage = ex.Message;
        }
    }

    public void StageFromDevice(DeviceRow row)
    {
        if (string.IsNullOrWhiteSpace(row.VendorId) || string.IsNullOrWhiteSpace(row.ProductId))
        {
            ErrorMessage = "이 장치에서 VID/PID를 읽지 못했습니다. 직접 입력하세요. 확인되지 않은 장치는 선택적 차단에서 허용되지 않습니다.";
            return;
        }

        NewVid = row.VendorId;
        NewPid = row.ProductId;
        NewSerial = row.Serial == "-" ? "" : row.Serial;
        NewName = row.Name;
        ErrorMessage = "";
    }

    public void ExportLogs(string path)
    {
        try
        {
            _session.ExportLogs(path);
            ErrorMessage = "";
            Reload();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or UsbAccessControlException)
        {
            ErrorMessage = ex.Message;
        }
    }

    public void SetPassword()
    {
        try
        {
            _session.SetAdminPassword(Password, NewPassword);
            Password = NewPassword;
            NewPassword = "";
            ErrorMessage = "";
            StatusText = "관리자 암호를 저장했습니다.";
            Reload();
        }
        catch (Exception ex) when (ex is UsbAccessControlException or UnauthorizedAccessException)
        {
            ErrorMessage = ex.Message;
        }
    }

    public void ClearPassword()
    {
        try
        {
            _session.ClearAdminPassword(Password);
            Password = "";
            ErrorMessage = "";
            StatusText = "관리자 암호를 해제했습니다.";
            Reload();
        }
        catch (Exception ex) when (ex is UsbAccessControlException or UnauthorizedAccessException)
        {
            ErrorMessage = ex.Message;
        }
    }

    public void ScanOnce()
    {
        try
        {
            var scan = _session.ScanAndEnforce();
            ErrorMessage = scan.Warnings.Count == 0 ? "" : string.Join(" ", scan.Warnings);
            Reload();
        }
        catch (Exception ex) when (ex is DeviceControlException or IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            ErrorMessage = ex.Message;
        }
    }

    private void ChangeMode(PolicyMode mode)
    {
        if (_suppress || _session.Document.Mode == mode)
        {
            return;
        }

        try
        {
            _session.SetMode(mode, Password);
            _confirmBlock = false;
            ErrorMessage = "";
            Reload();
        }
        catch (Exception ex) when (ex is UsbAccessControlException or UnauthorizedAccessException)
        {
            ErrorMessage = ex.Message;
            Reload();
        }
    }

    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }

        field = value;
        Notify(name);
    }

    private void Notify(string? name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
