using UsbAccessControl.Core;

namespace UsbAccessControl.Windows;

public sealed class RegistryPolicyEnforcer : IPolicyEnforcer
{
    private readonly IRegistryEditor _editor;

    public RegistryPolicyEnforcer(IRegistryEditor editor)
    {
        _editor = editor;
    }

    public void Apply(EnforcementPlan plan) => RegistryPlanApplier.Apply(plan, _editor);
}
