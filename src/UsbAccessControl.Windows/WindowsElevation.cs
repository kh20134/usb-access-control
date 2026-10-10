using System.Security.Principal;
using UsbAccessControl.Core;

namespace UsbAccessControl.Windows;

public sealed class WindowsElevationProbe : IElevationProbe
{
    public bool IsElevated
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}
