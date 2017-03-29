#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mdevice.h"
#include "m2minterfacefactory_stub.h"

bool m2minterfacefactory_stub::null_device;

M2MDevice* M2MInterfaceFactory::create_device()
{
    if (m2minterfacefactory_stub::null_device) {
        return NULL;
    }
    M2MDevice *device = M2MDevice::get_instance();
    return device;
}

