#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mdevice.h"

M2MDevice* M2MInterfaceFactory::create_device()
{
    M2MDevice *device = M2MDevice::get_instance();
    return device;
}

