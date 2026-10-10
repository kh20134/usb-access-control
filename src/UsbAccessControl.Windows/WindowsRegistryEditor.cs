using Microsoft.Win32;
using UsbAccessControl.Core;

namespace UsbAccessControl.Windows;

public sealed class WindowsRegistryEditor : IRegistryEditor, IRegistryReader
{
    public bool KeyExists(string keyPath)
    {
        using var root = Open();
        using var key = root.OpenSubKey(keyPath, writable: false);
        return key is not null;
    }

    public int? TryGetDword(string keyPath, string valueName)
    {
        using var root = Open();
        using var key = root.OpenSubKey(keyPath, writable: false);
        return key?.GetValue(valueName) is int number ? number : null;
    }

    public void SetDword(string keyPath, string valueName, int value)
    {
        using var root = Open();
        using var key = root.CreateSubKey(keyPath, writable: true)
            ?? throw new PolicyApplyException($"레지스트리 키를 만들지 못했습니다: HKLM\\{keyPath}");
        key.SetValue(valueName, value, RegistryValueKind.DWord);
    }

    private static RegistryKey Open() =>
        RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
}
