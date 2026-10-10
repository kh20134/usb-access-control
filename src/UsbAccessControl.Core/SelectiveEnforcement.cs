namespace UsbAccessControl.Core;

public enum DeviceObservationKind
{
    PresentAtStart,
    Inserted,
    Removed
}

public sealed record DeviceObservation(DeviceObservationKind Kind, UsbStorageDevice Device);

public sealed record DeviceControlAction(
    string InstanceId,
    UsbStorageDevice? Device,
    bool? Enable,
    EffectiveAccess Access,
    WhitelistEntry? Match,
    string Reason);

public sealed class DeviceWatchService
{
    private readonly Dictionary<string, UsbStorageDevice> _present = new(StringComparer.OrdinalIgnoreCase);
    private bool _hasBaseline;

    public void Reset()
    {
        _present.Clear();
        _hasBaseline = false;
    }

    public IReadOnlyList<DeviceObservation> Observe(
        IReadOnlyList<UsbStorageDevice> observed,
        IReadOnlyCollection<string>? suppressedRemovals = null)
    {
        var map = Index(observed);
        if (_hasBaseline && suppressedRemovals is not null)
        {
            foreach (var instanceId in suppressedRemovals)
            {
                if (!map.ContainsKey(instanceId) && _present.TryGetValue(instanceId, out var hidden))
                {
                    // A devnode we disabled can drop out of the present list while it is still plugged in.
                    map[instanceId] = hidden;
                }
            }
        }

        var events = new List<DeviceObservation>();
        if (!_hasBaseline)
        {
            _hasBaseline = true;
            events.AddRange(map.Values.Select(device => new DeviceObservation(DeviceObservationKind.PresentAtStart, device)));
        }
        else
        {
            foreach (var device in map.Values)
            {
                if (!_present.ContainsKey(device.InstanceId))
                {
                    events.Add(new DeviceObservation(DeviceObservationKind.Inserted, device));
                }
            }

            foreach (var previous in _present.Values)
            {
                if (!map.ContainsKey(previous.InstanceId))
                {
                    events.Add(new DeviceObservation(DeviceObservationKind.Removed, previous));
                }
            }
        }

        _present.Clear();
        foreach (var pair in map)
        {
            _present[pair.Key] = pair.Value;
        }

        return events;
    }

    public static Dictionary<string, UsbStorageDevice> Index(IReadOnlyList<UsbStorageDevice> observed)
    {
        var map = new Dictionary<string, UsbStorageDevice>(StringComparer.OrdinalIgnoreCase);
        foreach (var device in observed)
        {
            if (!device.IsMassStorage || !DeviceIdParser.IsUsbStorInstance(device.InstanceId))
            {
                continue;
            }

            map[device.InstanceId.Trim()] = device;
        }

        return map;
    }
}

public static class SelectiveEnforcement
{
    public static IReadOnlyList<DeviceControlAction> Decide(
        EnforcementPlan plan,
        IReadOnlyList<WhitelistEntry> whitelist,
        IReadOnlyList<UsbStorageDevice> present,
        IReadOnlyCollection<string> previouslyDisabled)
    {
        var actions = new List<DeviceControlAction>();
        var disabled = new HashSet<string>(previouslyDisabled.Where(DeviceIdParser.IsUsbStorInstance), StringComparer.OrdinalIgnoreCase);
        var presentIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var device in DeviceWatchService.Index(present).Values)
        {
            presentIds.Add(device.InstanceId);
            var match = WhitelistMatcher.FindMatch(whitelist, device);
            var access = AccessDecider.Enforceable(plan, match is not null);
            if (plan.SelectiveDeviceControl)
            {
                if (access == EffectiveAccess.Block)
                {
                    actions.Add(new DeviceControlAction(
                        device.InstanceId,
                        device,
                        false,
                        access,
                        match,
                        "화이트리스트와 일치하지 않아 USBSTOR 장치 노드를 비활성화합니다."));
                }
                else if (disabled.Contains(device.InstanceId))
                {
                    actions.Add(new DeviceControlAction(
                        device.InstanceId,
                        device,
                        true,
                        access,
                        match,
                        "승인된 장치이므로 이전에 끈 USBSTOR 장치 노드를 다시 켭니다."));
                }
                else
                {
                    actions.Add(new DeviceControlAction(
                        device.InstanceId,
                        device,
                        null,
                        access,
                        match,
                        match is null
                            ? "장치 노드를 바꾸지 않습니다."
                            : $"화이트리스트 '{match.DisplayName}'과 일치합니다. 장치 노드를 유지합니다."));
                }
            }
            else if (disabled.Contains(device.InstanceId))
            {
                actions.Add(new DeviceControlAction(
                    device.InstanceId,
                    device,
                    true,
                    access,
                    match,
                    "선택적 차단이 아니므로 이전에 끈 USBSTOR 장치 노드를 다시 켭니다."));
            }
            else
            {
                actions.Add(new DeviceControlAction(
                    device.InstanceId,
                    device,
                    null,
                    access,
                    match,
                    DescribePassive(plan, access, match)));
            }
        }

        if (!plan.SelectiveDeviceControl)
        {
            foreach (var instanceId in disabled)
            {
                if (presentIds.Contains(instanceId))
                {
                    continue;
                }

                actions.Add(new DeviceControlAction(
                    instanceId,
                    null,
                    true,
                    EffectiveAccess.Allow,
                    null,
                    "이전에 끈 장치가 현재 목록에 없어도, 선택적 차단을 해제했으므로 다시 켜기를 시도합니다."));
            }
        }

        return actions;
    }

    private static string DescribePassive(EnforcementPlan plan, EffectiveAccess access, WhitelistEntry? match)
    {
        if (plan.WhitelistWriteExemptionUnsupported && match is not null)
        {
            return $"화이트리스트 '{match.DisplayName}'과 일치하지만, 읽기 전용은 전역 정책이라 쓰기는 허용되지 않습니다.";
        }

        return access switch
        {
            EffectiveAccess.Allow => "기본 정책에 따라 허용됩니다. 장치 노드를 바꾸지 않습니다.",
            EffectiveAccess.ReadOnly => "기본 정책에 따라 읽기 전용입니다. 장치 노드를 바꾸지 않습니다.",
            _ => "기본 정책에 따라 차단됩니다. 전역 레지스트리 정책을 사용하며 장치 노드를 개별적으로 끄지 않습니다."
        };
    }
}
