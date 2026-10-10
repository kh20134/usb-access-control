namespace UsbAccessControl.Core;

public class UsbAccessControlException : Exception
{
    public UsbAccessControlException(string message) : base(message)
    {
    }

    public UsbAccessControlException(string message, Exception inner) : base(message, inner)
    {
    }
}

public sealed class AuthorizationException : UsbAccessControlException
{
    public AuthorizationException(string message) : base(message)
    {
    }
}

public sealed class ValidationException : UsbAccessControlException
{
    public ValidationException(string message) : base(message)
    {
    }
}

public sealed class PolicyApplyException : UsbAccessControlException
{
    public PolicyApplyException(string message) : base(message)
    {
    }

    public PolicyApplyException(string message, Exception inner) : base(message, inner)
    {
    }
}

public sealed class DeviceControlException : UsbAccessControlException
{
    public DeviceControlException(string message, bool deviceMissing = false) : base(message)
    {
        DeviceMissing = deviceMissing;
    }

    public bool DeviceMissing { get; }
}
