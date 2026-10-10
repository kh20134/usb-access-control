using System.Security.AccessControl;
using System.Security.Principal;
using UsbAccessControl.Core;

namespace UsbAccessControl.Windows;

public sealed class WindowsAclProtector : IFileProtector
{
    public void ProtectDirectory(string directory)
    {
        var info = new DirectoryInfo(directory);
        var security = info.GetAccessControl();
        Replace(security, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        info.SetAccessControl(security);
    }

    public void ProtectFile(string path)
    {
        var info = new FileInfo(path);
        var security = info.GetAccessControl();
        Replace(security, InheritanceFlags.None);
        info.SetAccessControl(security);
    }

    private static void Replace(FileSystemSecurity security, InheritanceFlags inheritance)
    {
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var existing = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        foreach (var rule in existing)
        {
            security.RemoveAccessRule(rule);
        }

        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        security.AddAccessRule(new FileSystemAccessRule(
            administrators,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            system,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
    }
}
