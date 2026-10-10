namespace UsbAccessControl.Core;

public sealed record ApplyResult(EnforcementPlan Plan, IReadOnlyList<string> Warnings);

public sealed class ScanOutcome
{
    public required IReadOnlyList<UsbStorageDevice> Devices { get; init; }
    public required IReadOnlyList<DeviceObservation> Observations { get; init; }
    public required IReadOnlyList<DeviceControlAction> Actions { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public required IReadOnlyDictionary<string, string> ControlResults { get; init; }
}

public sealed class PolicySession
{
    private readonly PolicyStore _store;
    private readonly AuditLog _audit;
    private readonly EnforcementStateStore _stateStore;
    private readonly IUserContext _user;
    private readonly TimeProvider _time;
    private readonly IPolicyEnforcer _enforcer;
    private readonly IDeviceEnumerator _devices;
    private readonly IDeviceController _controller;
    private readonly IElevationProbe _elevation;
    private readonly IRegistryReader? _registryReader;
    private readonly DeviceWatchService _watch = new();
    private readonly object _gate = new();
    private PolicyDocument _document;
    private Dictionary<string, string> _controlResults = new(StringComparer.OrdinalIgnoreCase);

    public PolicySession(
        PolicyStore store,
        AuditLog audit,
        EnforcementStateStore stateStore,
        IUserContext user,
        TimeProvider time,
        IPolicyEnforcer enforcer,
        IDeviceEnumerator devices,
        IDeviceController controller,
        IElevationProbe elevation,
        SessionOptions options,
        IRegistryReader? registryReader = null)
    {
        _store = store;
        _audit = audit;
        _stateStore = stateStore;
        _user = user;
        _time = time;
        _enforcer = enforcer;
        _devices = devices;
        _controller = controller;
        _elevation = elevation;
        _registryReader = registryReader;
        Options = options;
        var loaded = store.LoadOrCreate();
        _document = loaded.Document;
        LoadWarnings = loaded.Warnings;
    }

    public SessionOptions Options { get; }
    public PolicyDocument Document => _document;
    public string UserName => _user.UserName;
    public string MachineName => _user.MachineName;
    public IReadOnlyList<string> LoadWarnings { get; private set; }
    public IReadOnlyDictionary<string, string> ControlResults => _controlResults;
    public bool IsElevated => _elevation.IsElevated;

    public EnforcementPlan Preview() =>
        EnforcementPlanner.Create(_document.Mode, _document.Whitelist.Count > 0);

    public IReadOnlyList<RegistryObservation> ReadRegistryDrift()
    {
        if (_registryReader is null)
        {
            return Array.Empty<RegistryObservation>();
        }

        return RegistryDrift.Compare(Preview(), _registryReader);
    }

    public void SetMode(PolicyMode mode, string? password)
    {
        lock (_gate)
        {
            AuthorizeOrLog(password);
            if (_document.Mode == mode)
            {
                return;
            }

            _document.Mode = mode;
            Touch();
            _store.Save(_document);
        }
    }

    public WhitelistEntry AddWhitelist(
        string vendorId,
        string productId,
        string? serialNumber,
        string displayName,
        string? note,
        string? password)
    {
        lock (_gate)
        {
            AuthorizeOrLog(password);
            if (_document.Whitelist.Count >= WhitelistRules.MaxEntries)
            {
                throw new ValidationException($"화이트리스트는 {WhitelistRules.MaxEntries}개까지 저장할 수 있습니다.");
            }

            var entry = WhitelistRules.Create(vendorId, productId, serialNumber, displayName, note, _time.GetUtcNow());
            if (_document.Whitelist.Any(existing => WhitelistRules.IsSameIdentity(existing, entry)))
            {
                throw new ValidationException("같은 VID, PID, 일련번호의 항목이 이미 있습니다.");
            }

            _document.Whitelist.Add(entry);
            Touch();
            _store.Save(_document);
            WriteAudit(
                AuditAction.WhitelistAdded,
                result: "성공",
                detail: $"{entry.DisplayName} ({entry.VendorId}:{entry.ProductId})",
                vendorId: entry.VendorId,
                productId: entry.ProductId,
                serial: entry.SerialNumber,
                deviceName: entry.DisplayName);
            return entry;
        }
    }

    public bool RemoveWhitelist(Guid id, string? password)
    {
        lock (_gate)
        {
            AuthorizeOrLog(password);
            var entry = _document.Whitelist.FirstOrDefault(item => item.Id == id);
            if (entry is null)
            {
                return false;
            }

            _document.Whitelist.Remove(entry);
            Touch();
            _store.Save(_document);
            WriteAudit(
                AuditAction.WhitelistRemoved,
                result: "성공",
                detail: entry.DisplayName,
                vendorId: entry.VendorId,
                productId: entry.ProductId,
                serial: entry.SerialNumber,
                deviceName: entry.DisplayName);
            return true;
        }
    }

    public void SetAdminPassword(string? currentPassword, string newPassword)
    {
        lock (_gate)
        {
            AuthorizeOrLog(currentPassword);
            _document.AdminPassword = PasswordHasher.Create(newPassword);
            Touch();
            _store.Save(_document);
            WriteAudit(AuditAction.PasswordSet, result: "성공", detail: "관리자 암호를 설정했습니다.");
        }
    }

    public void ClearAdminPassword(string? currentPassword)
    {
        lock (_gate)
        {
            AuthorizeOrLog(currentPassword);
            _document.AdminPassword = null;
            Touch();
            _store.Save(_document);
            WriteAudit(AuditAction.PasswordCleared, result: "성공", detail: "관리자 암호를 해제했습니다.");
        }
    }

    public ApplyResult Apply(string? password)
    {
        lock (_gate)
        {
            AuthorizeOrLog(password);
            EnsureHostCanApply();
            var plan = Preview();
            try
            {
                _enforcer.Apply(plan);
            }
            catch (Exception ex) when (ex is PolicyApplyException or UnauthorizedAccessException or IOException or InvalidOperationException)
            {
                WriteAudit(AuditAction.PolicyRejected, result: "실패", detail: ex.Message);
                throw;
            }

            var scan = ScanAndEnforceCore();
            _document.AppliedFingerprint = _document.DesiredFingerprint();
            _document.AppliedAt = _time.GetUtcNow();
            _document.UpdatedAt = _document.AppliedAt.Value;
            _document.UpdatedBy = _user.UserName;
            _store.Save(_document);
            var detail = _optionsSimulationPrefix() + string.Join(" ", plan.Notes);
            WriteAudit(AuditAction.PolicyApplied, result: scan.Warnings.Count == 0 ? "성공" : "부분 성공", detail: detail);
            return new ApplyResult(plan, scan.Warnings);
        }
    }

    public ScanOutcome ScanAndEnforce()
    {
        lock (_gate)
        {
            return ScanAndEnforceCore();
        }
    }

    public IReadOnlyList<UsbStorageDevice> ListDevices()
    {
        lock (_gate)
        {
            return _devices.ListMassStorageDevices();
        }
    }

    public EffectiveAccess Explain(UsbStorageDevice device)
    {
        var match = WhitelistMatcher.FindMatch(_document.Whitelist, device);
        return AccessDecider.Enforceable(Preview(), match is not null);
    }

    public IReadOnlyList<AuditEvent> RecentLogs(int limit)
    {
        if (limit < 1)
        {
            throw new ValidationException("로그 개수는 1 이상이어야 합니다.");
        }

        return _audit.ReadAll().TakeLast(limit).ToArray();
    }

    public void ExportLogs(string path)
    {
        lock (_gate)
        {
            var csv = CsvExporter.Export(_audit.ReadAll());
            var directory = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(path, csv, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            WriteAudit(AuditAction.LogExported, result: "성공", detail: path);
        }
    }

    public void MarkMonitor(bool started)
    {
        lock (_gate)
        {
            WriteAudit(
                started ? AuditAction.MonitorStarted : AuditAction.MonitorStopped,
                result: "성공",
                detail: started
                    ? "USB 저장장치 감시를 시작했습니다."
                    : "USB 저장장치 감시를 중지했습니다.");
        }
    }

    private ScanOutcome ScanAndEnforceCore()
    {
        var devices = _devices.ListMassStorageDevices();
        var state = _stateStore.Load();
        var observations = _watch.Observe(devices, state.DisabledInstanceIds);
        var plan = Preview();
        var actions = SelectiveEnforcement.Decide(plan, _document.Whitelist, devices, state.DisabledInstanceIds);
        var warnings = new List<string>();
        var disabled = new HashSet<string>(state.DisabledInstanceIds.Where(DeviceIdParser.IsUsbStorInstance), StringComparer.OrdinalIgnoreCase);
        var results = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var action in actions)
        {
            if (action.Enable is null)
            {
                results[action.InstanceId] = "변경 없음";
                continue;
            }

            try
            {
                var outcome = _controller.SetMassStorageEnabled(action.InstanceId, action.Enable.Value);
                switch (outcome)
                {
                    case DeviceControlOutcome.Changed:
                        if (action.Enable.Value)
                        {
                            disabled.Remove(action.InstanceId);
                        }
                        else
                        {
                            disabled.Add(action.InstanceId);
                        }

                        results[action.InstanceId] = "성공";
                        break;
                    case DeviceControlOutcome.NotFound:
                        disabled.Remove(action.InstanceId);
                        results[action.InstanceId] = "장치 없음";
                        warnings.Add($"{action.InstanceId}: 장치 노드를 찾지 못했습니다.");
                        break;
                    default:
                        results[action.InstanceId] = "실패";
                        warnings.Add($"{action.InstanceId}: 장치 노드를 바꾸지 못했습니다.");
                        break;
                }
            }
            catch (Exception ex) when (ex is DeviceControlException or InvalidOperationException or UnauthorizedAccessException or IOException or PlatformNotSupportedException)
            {
                if (ex is DeviceControlException { DeviceMissing: true })
                {
                    disabled.Remove(action.InstanceId);
                    results[action.InstanceId] = "장치 없음";
                }
                else
                {
                    results[action.InstanceId] = "실패";
                }

                warnings.Add(ex.Message);
            }
        }

        state.DisabledInstanceIds = disabled.OrderBy(id => id, StringComparer.OrdinalIgnoreCase).ToList();
        _stateStore.Save(state);
        _controlResults = results;

        foreach (var observation in observations)
        {
            var action = actions.FirstOrDefault(item =>
                item.InstanceId.Equals(observation.Device.InstanceId, StringComparison.OrdinalIgnoreCase));
            WriteDeviceObservation(observation, action, results);
        }

        return new ScanOutcome
        {
            Devices = devices,
            Observations = observations,
            Actions = actions,
            Warnings = warnings,
            ControlResults = results
        };
    }

    private void WriteDeviceObservation(
        DeviceObservation observation,
        DeviceControlAction? action,
        IReadOnlyDictionary<string, string> results)
    {
        var device = observation.Device;
        if (observation.Kind == DeviceObservationKind.Removed)
        {
            WriteAudit(
                AuditAction.DeviceRemoved,
                result: "기록",
                detail: "장치가 분리되었습니다.",
                instanceId: device.InstanceId,
                vendorId: device.VendorId,
                productId: device.ProductId,
                serial: device.SerialNumber,
                deviceName: device.FriendlyName);
            return;
        }

        var access = action?.Access ?? Explain(device);
        var auditAction = access switch
        {
            EffectiveAccess.Allow => AuditAction.DeviceAllowed,
            EffectiveAccess.ReadOnly => AuditAction.DeviceReadOnly,
            _ => AuditAction.DeviceBlocked
        };
        results.TryGetValue(device.InstanceId, out var control);
        var kind = observation.Kind == DeviceObservationKind.PresentAtStart ? "초기 검색" : "연결";
        var reason = action?.Reason ?? "";
        var detail = control is "실패" or "장치 없음"
            ? $"{kind}. {reason} 결과: {control}."
            : $"{kind}. {reason}";
        WriteAudit(
            auditAction,
            result: control is "실패" ? "실패" : access.ToKorean(),
            detail: detail,
            instanceId: device.InstanceId,
            vendorId: device.VendorId,
            productId: device.ProductId,
            serial: device.SerialNumber,
            deviceName: device.FriendlyName);
    }

    private void EnsureHostCanApply()
    {
        if (!Options.RequireWindowsHost)
        {
            return;
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows 레지스트리 정책 적용은 Windows 10/11에서만 가능합니다.");
        }

        if (!_elevation.IsElevated)
        {
            throw new UnauthorizedAccessException("정책을 Windows에 적용하려면 관리자 권한으로 다시 실행하세요.");
        }
    }

    private void AuthorizeOrLog(string? password)
    {
        try
        {
            AdminAuthorizer.EnsureAuthorized(_document, password);
        }
        catch (AuthorizationException)
        {
            WriteAudit(AuditAction.PolicyRejected, result: "거부", detail: "관리자 암호가 올바르지 않습니다.");
            throw;
        }
    }

    private void Touch()
    {
        _document.UpdatedAt = _time.GetUtcNow();
        _document.UpdatedBy = _user.UserName;
    }

    private string _optionsSimulationPrefix() =>
        Options.Simulation ? "시뮬레이션입니다. Windows 레지스트리는 변경하지 않았습니다. " : "";

    private void WriteAudit(
        AuditAction action,
        string result,
        string? detail,
        string? instanceId = null,
        string? vendorId = null,
        string? productId = null,
        string? serial = null,
        string? deviceName = null)
    {
        _audit.Append(new AuditEvent
        {
            Timestamp = _time.GetUtcNow(),
            UserName = _user.UserName,
            MachineName = _user.MachineName,
            Action = action,
            InstanceId = instanceId,
            VendorId = vendorId,
            ProductId = productId,
            SerialNumber = serial,
            DeviceName = deviceName,
            PolicyMode = _document.Mode.ToKorean(),
            Result = result,
            Detail = detail
        });
    }
}
