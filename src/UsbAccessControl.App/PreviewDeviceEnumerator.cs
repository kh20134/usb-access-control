using UsbAccessControl.Core;

namespace UsbAccessControl.App;

public sealed class PreviewDeviceEnumerator : IDeviceEnumerator
{
    public IReadOnlyList<UsbStorageDevice> ListMassStorageDevices() =>
    [
        new UsbStorageDevice
        {
            InstanceId = @"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001230101123456&0",
            VendorId = "0781",
            ProductId = "5581",
            SerialNumber = "4C530001230101123456",
            FriendlyName = "SanDisk Ultra",
            IsMassStorage = true
        },
        new UsbStorageDevice
        {
            InstanceId = @"USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER&REV_1.00\001CC0EC34D8F123456789&0",
            VendorId = "0951",
            ProductId = "1666",
            SerialNumber = "001CC0EC34D8F123456789",
            FriendlyName = "Kingston DataTraveler",
            IsMassStorage = true
        }
    ];
}
