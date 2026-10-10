namespace UsbAccessControl.Core;

public enum EffectiveAccess
{
    Allow,
    ReadOnly,
    Block
}

public static class EffectiveAccessNames
{
    public static string ToKorean(this EffectiveAccess access) => access switch
    {
        EffectiveAccess.Allow => "허용",
        EffectiveAccess.ReadOnly => "읽기 전용",
        _ => "차단"
    };
}

public static class AccessDecider
{
    public static EffectiveAccess Intended(PolicyMode mode, bool whitelisted)
    {
        if (whitelisted)
        {
            return EffectiveAccess.Allow;
        }

        return mode switch
        {
            PolicyMode.Allow => EffectiveAccess.Allow,
            PolicyMode.ReadOnly => EffectiveAccess.ReadOnly,
            PolicyMode.Block => EffectiveAccess.Block,
            _ => EffectiveAccess.Block
        };
    }

    /// <summary>
    /// Access that the Windows mechanisms in <see cref="EnforcementPlanner"/> can actually apply.
    /// A whitelist match does not override a machine-wide read-only policy.
    /// </summary>
    public static EffectiveAccess Enforceable(EnforcementPlan plan, bool whitelisted)
    {
        if (plan.SelectiveDeviceControl)
        {
            return whitelisted ? EffectiveAccess.Allow : EffectiveAccess.Block;
        }

        if (plan.WhitelistWriteExemptionUnsupported && whitelisted && plan.Mode == PolicyMode.ReadOnly)
        {
            return EffectiveAccess.ReadOnly;
        }

        return Intended(plan.Mode, whitelisted);
    }
}

public static class RegistryPolicyPaths
{
    public const string UsbStor = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
    public const string UsbStorStartValue = "Start";
    public const int UsbStorDemandStart = 3;
    public const int UsbStorDisabled = 4;

    public const string WriteProtectKey = @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";
    public const string WriteProtectValue = "WriteProtect";

    public const string RemovableStorageKey = @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices";
    public const string DenyAllValue = "Deny_All";

    /// <summary>
    /// Removable Disks class used by the "Removable Storage Access" administrative template.
    /// </summary>
    public const string RemovableDiskGuid = "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";

    public const string DenyReadValue = "Deny_Read";
    public const string DenyWriteValue = "Deny_Write";

    public static string RemovableDiskKey => RemovableStorageKey + "\\" + RemovableDiskGuid;
}

public sealed record PlannedRegistryValue(string KeyPath, string ValueName, int Dword);

public sealed record EnforcementPlan
{
    public required PolicyMode Mode { get; init; }
    public required bool WhitelistPresent { get; init; }
    public required int UsbStorStart { get; init; }
    public required bool WriteProtect { get; init; }
    public required bool DenyAll { get; init; }
    public required bool DenyRead { get; init; }
    public required bool DenyWrite { get; init; }
    public required bool SelectiveDeviceControl { get; init; }
    public required bool WhitelistWriteExemptionUnsupported { get; init; }
    public required IReadOnlyList<string> Notes { get; init; }

    public IReadOnlyList<PlannedRegistryValue> RegistryValues()
    {
        return
        [
            new(RegistryPolicyPaths.UsbStor, RegistryPolicyPaths.UsbStorStartValue, UsbStorStart),
            new(RegistryPolicyPaths.WriteProtectKey, RegistryPolicyPaths.WriteProtectValue, WriteProtect ? 1 : 0),
            new(RegistryPolicyPaths.RemovableStorageKey, RegistryPolicyPaths.DenyAllValue, DenyAll ? 1 : 0),
            new(RegistryPolicyPaths.RemovableDiskKey, RegistryPolicyPaths.DenyReadValue, DenyRead ? 1 : 0),
            new(RegistryPolicyPaths.RemovableDiskKey, RegistryPolicyPaths.DenyWriteValue, DenyWrite ? 1 : 0)
        ];
    }
}

public static class EnforcementPlanner
{
    public static EnforcementPlan Create(PolicyMode mode, bool hasWhitelistEntries)
    {
        return mode switch
        {
            PolicyMode.Allow => Allow(hasWhitelistEntries),
            PolicyMode.ReadOnly => ReadOnly(hasWhitelistEntries),
            PolicyMode.Block when !hasWhitelistEntries => BlockAll(),
            PolicyMode.Block => BlockExceptWhitelist(),
            _ => BlockAll()
        };
    }

    private static EnforcementPlan Allow(bool hasWhitelistEntries) => new()
    {
        Mode = PolicyMode.Allow,
        WhitelistPresent = hasWhitelistEntries,
        UsbStorStart = RegistryPolicyPaths.UsbStorDemandStart,
        WriteProtect = false,
        DenyAll = false,
        DenyRead = false,
        DenyWrite = false,
        SelectiveDeviceControl = false,
        WhitelistWriteExemptionUnsupported = false,
        Notes =
        [
            "USBSTOR 서비스를 수동 시작(3)으로 두고, 이동식 저장장치 거부 값과 WriteProtect를 0으로 둡니다.",
            hasWhitelistEntries
                ? "기본 정책이 허용이므로 화이트리스트는 접근을 더 제한하지 않습니다. 승인된 장치만 쓰려면 기본 정책을 차단으로 두세요."
                : "USB 대용량 저장장치 읽기와 쓰기를 막지 않습니다."
        ]
    };

    private static EnforcementPlan ReadOnly(bool hasWhitelistEntries) => new()
    {
        Mode = PolicyMode.ReadOnly,
        WhitelistPresent = hasWhitelistEntries,
        UsbStorStart = RegistryPolicyPaths.UsbStorDemandStart,
        WriteProtect = true,
        DenyAll = false,
        DenyRead = false,
        DenyWrite = true,
        SelectiveDeviceControl = false,
        WhitelistWriteExemptionUnsupported = hasWhitelistEntries,
        Notes = hasWhitelistEntries
            ?
            [
                "이동식 디스크 클래스에 Deny_Write=1, Deny_Read=0을 쓰고 StorageDevicePolicies\\WriteProtect=1을 켭니다.",
                "이 쓰기 금지는 PC 전역입니다. 필터 드라이버가 없으므로 화이트리스트 장치만 쓰기를 허용할 수 없습니다.",
                "Deny_All은 켜지 않습니다. Deny_All은 읽기까지 막으며 개별 설정보다 우선합니다.",
                "WriteProtect는 UASP 장치와 MTP(휴대폰)에 적용되지 않을 수 있습니다. 그룹 정책 쓰기 거부가 기본 수단입니다."
            ]
            :
            [
                "이동식 디스크는 읽을 수 있고 쓰기는 거부됩니다.",
                "StorageDevicePolicies\\WriteProtect는 보조 수단입니다. UASP 장치에는 적용되지 않을 수 있습니다.",
                "이미 마운트된 볼륨은 다시 연결하거나 다시 로그온해야 정책이 반영될 수 있습니다."
            ]
    };

    private static EnforcementPlan BlockAll() => new()
    {
        Mode = PolicyMode.Block,
        WhitelistPresent = false,
        UsbStorStart = RegistryPolicyPaths.UsbStorDisabled,
        WriteProtect = false,
        DenyAll = true,
        DenyRead = true,
        DenyWrite = true,
        SelectiveDeviceControl = false,
        WhitelistWriteExemptionUnsupported = false,
        Notes =
        [
            "USBSTOR 서비스를 사용 안 함(4)으로 두고, 이동식 저장장치 전체 거부(Deny_All)와 이동식 디스크 읽기/쓰기 거부를 켭니다.",
            "Deny_All은 CD, SD, WPD/MTP를 포함한 이동식 저장 클래스 전체에 적용됩니다. USB 키보드와 마우스는 USBSTOR가 아니라 영향받지 않습니다.",
            "이미 연결된 볼륨은 장치를 다시 꽂거나 PC를 다시 시작하기 전까지 남아 있을 수 있습니다."
        ]
    };

    private static EnforcementPlan BlockExceptWhitelist() => new()
    {
        Mode = PolicyMode.Block,
        WhitelistPresent = true,
        UsbStorStart = RegistryPolicyPaths.UsbStorDemandStart,
        WriteProtect = false,
        DenyAll = false,
        DenyRead = false,
        DenyWrite = false,
        SelectiveDeviceControl = true,
        WhitelistWriteExemptionUnsupported = false,
        Notes =
        [
            "승인된 장치만 허용하려면 USBSTOR와 전역 거부를 켜 두면 승인 장치까지 막힙니다. 그래서 레지스트리 거부는 끄고, USBSTOR 장치 노드만 선택적으로 비활성화합니다.",
            "선택적 제어는 이 프로그램이 관리자 권한으로 감시 중일 때만 유지됩니다. 프로세스가 없으면 새로 꽂은 장치가 열릴 수 있습니다.",
            "VID/PID를 확인하지 못한 저장장치는 허용하지 않습니다."
        ]
    };
}

public interface IRegistryEditor
{
    bool KeyExists(string keyPath);
    void SetDword(string keyPath, string valueName, int value);
}

public interface IRegistryReader
{
    int? TryGetDword(string keyPath, string valueName);
}

public sealed record RegistryObservation(
    string KeyPath,
    string ValueName,
    int? Actual,
    int Expected,
    bool Matches);

public static class RegistryPlanApplier
{
    public static void Apply(EnforcementPlan plan, IRegistryEditor editor)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(editor);

        var values = plan.RegistryValues();
        if (values.Any(value => value.KeyPath.Equals(RegistryPolicyPaths.UsbStor, StringComparison.OrdinalIgnoreCase))
            && !editor.KeyExists(RegistryPolicyPaths.UsbStor))
        {
            throw new PolicyApplyException(
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR 키가 없습니다. USB 저장 드라이버 구성이 예상과 달라 레지스트리를 변경하지 않았습니다.");
        }

        foreach (var value in values)
        {
            editor.SetDword(value.KeyPath, value.ValueName, value.Dword);
        }
    }
}

public static class RegistryDrift
{
    public static IReadOnlyList<RegistryObservation> Compare(EnforcementPlan plan, IRegistryReader reader)
    {
        return plan.RegistryValues()
            .Select(value =>
            {
                var actual = reader.TryGetDword(value.KeyPath, value.ValueName);
                return new RegistryObservation(value.KeyPath, value.ValueName, actual, value.Dword, actual == value.Dword);
            })
            .ToArray();
    }
}

public static class PolicyStatusText
{
    public static string Build(PolicyDocument document, EnforcementPlan plan)
    {
        var applied = document.IsApplied ? "이 PC에 적용됨" : "아직 이 PC에 적용되지 않음";
        var scope = plan.SelectiveDeviceControl
            ? "승인된 USB만 허용"
            : plan.WhitelistWriteExemptionUnsupported
                ? "읽기 전용은 전역 정책이라 화이트리스트도 쓸 수 없음"
                : document.Mode == PolicyMode.Allow && document.Whitelist.Count > 0
                    ? "기본 정책이 허용이라 화이트리스트는 예외가 아님"
                    : "모든 USB 저장장치에 기본 정책 적용";
        return $"{document.Mode.ToKorean()} · {scope} · {applied}";
    }
}
