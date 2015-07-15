
#include "lwm2m-client/m2mconnectionhandler.h"
#include "lwm2m-client/m2mconnectionsecurity.h"
#include "lwm2m-client/m2mtimer.h"
#include "lwm2m-client/m2msecurity.h"
#include <string.h>
#include "lwm2m-client-mbedtls/m2mconnectionsecuritypimpl.h"

M2MConnectionSecurity::M2MConnectionSecurity()
{
    _private_impl = new M2MConnectionSecurityPimpl();
}

M2MConnectionSecurity::~M2MConnectionSecurity(){
    delete _private_impl;
}

void M2MConnectionSecurity::reset(){
    _private_impl->reset();
}

int M2MConnectionSecurity::init(const M2MSecurity *security){
    return _private_impl->init(security);
}

int M2MConnectionSecurity::start_connecting_non_blocking(M2MConnectionHandler* connHandler)
{
    return _private_impl->start_connecting_non_blocking(connHandler);
}

int M2MConnectionSecurity::continue_connecting()
{
    return _private_impl->continue_connecting();
}

int M2MConnectionSecurity::connect(M2MConnectionHandler* connHandler){
    return _private_impl->connect(connHandler);
}

int M2MConnectionSecurity::send_message(unsigned char *message, int len){
    return _private_impl->send_message(message, len);
}

int M2MConnectionSecurity::read(unsigned char* buffer, uint16_t len){
    return _private_impl->read(buffer, len);
}
