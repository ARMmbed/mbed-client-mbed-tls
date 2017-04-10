/*
 * Copyright (c) 2015 - 2017 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbed-client/m2mconnectionhandler.h"
#include "mbed-client-mbedtls/m2mconnectionsecuritypimpl.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-trace/mbed_trace.h"
#include "pal.h"
#include "m2mdevice.h"
#include "m2minterfacefactory.h"
#include <string.h>

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#define TRACE_GROUP "mClt"

M2MConnectionSecurityPimpl::M2MConnectionSecurityPimpl(M2MConnectionSecurity::SecurityMode mode)
    :_init_done(M2MConnectionSecurityPimpl::INIT_NOT_STARTED),
     _conf(0),
     _ssl(0),
     _sec_mode(mode)
{
        memset(&_entropy, 0, sizeof(entropy_cb));
}

M2MConnectionSecurityPimpl::~M2MConnectionSecurityPimpl()
{
    if(_init_done){
        pal_tlsConfigurationFree(&_conf);
        if(_init_done == M2MConnectionSecurityPimpl::INIT_DONE){
            pal_freeTLS(&_ssl);
        }
    }
}

void M2MConnectionSecurityPimpl::reset()
{
    if(_init_done){
        pal_tlsConfigurationFree(&_conf);
        if(_init_done == M2MConnectionSecurityPimpl::INIT_DONE){
            pal_freeTLS(&_ssl);
        }
    }
    _init_done = M2MConnectionSecurityPimpl::INIT_NOT_STARTED;
}

int M2MConnectionSecurityPimpl::init(const M2MSecurity *security)
{
    tr_debug("M2MConnectionSecurityPimpl::init");

    if(!security){
        tr_error("M2MConnectionSecurityPimpl Security NULL.");
        return -1;
    }

    if(_entropy.entropy_source_ptr) {
        if(PAL_SUCCESS != pal_addEntropySource(_entropy.entropy_source_ptr)){
            return -1;
        }
    }

    palTLSTransportMode_t mode = PAL_DTLS_MODE;
    if(_sec_mode == M2MConnectionSecurity::TLS){
        mode = PAL_TLS_MODE;
    }

    if(PAL_SUCCESS != pal_initTLSConfiguration(&_conf, mode)){
        tr_error("pal_initTLSConfiguration failed");
        return -1;
    }

    _init_done = M2MConnectionSecurityPimpl::INIT_CONFIGURING;


    if(_sec_mode == M2MConnectionSecurity::DTLS){
        pal_setHandShakeTimeOut(_conf, 20000);
    }

    M2MSecurity::SecurityModeType cert_mode =
            (M2MSecurity::SecurityModeType)security->resource_value_int(M2MSecurity::SecurityMode);

    if( cert_mode == M2MSecurity::Certificate ){

        palX509_t owncert;
        palPrivateKey_t privateKey;
        palX509_t caChain;

        // Check if we are connecting to M2MServer and check if server certificate is valid, no need to do this
        // for Bootstrap currently
        if (security->server_type() == M2MSecurity::M2MServer && !check_security_object_validity(security)) {
            tr_error("M2MConnectionSecurityPimpl::init - M2MServer certificate invalid! - To be fixed when we are sure we have RTC even in direct LWM2M case");
            //return -1;
        }

        owncert.size = 1 + security->resource_value_buffer(M2MSecurity::PublicKey, (const uint8_t*&)owncert.buffer);
        privateKey.size = 1 + security->resource_value_buffer(M2MSecurity::Secretkey, (const uint8_t*&)privateKey.buffer);
        caChain.size = 1 + security->resource_value_buffer(M2MSecurity::ServerPublicKey, (const uint8_t*&)caChain.buffer);

        if(PAL_SUCCESS != pal_setOwnCertAndPrivateKey(_conf, &owncert, &privateKey)){
            tr_error("pal_setOwnCertAndPrivateKey failed");
            return -1;
        }
        if(PAL_SUCCESS != pal_setCAChain(_conf, &caChain, NULL)){
            tr_error("pal_setCAChain failed");
            return -1;
        }

    }else if(cert_mode == M2MSecurity::Psk){

        uint8_t *identity;
        uint32_t identityLen;
        uint8_t *psk;
        uint32_t pskLen;

        pskLen = security->resource_value_buffer(M2MSecurity::PublicKey, psk);
        identityLen = security->resource_value_buffer(M2MSecurity::Secretkey, identity);

        if(PAL_SUCCESS != pal_setPSK(_conf, identity, identityLen, psk, pskLen)){
            tr_error("pal_setPSK failed");
            return -1;
        }

    }else{
        tr_error("Security mode not set");
        return -1;

    }

    if(PAL_SUCCESS != pal_initTLS(_conf, &_ssl)){
        tr_error("pal_initTLS failed");
        return -1;
    }

    if(PAL_SUCCESS != pal_tlsSetSocket(_conf, &tls_socket)){
        tr_error("pal_tlsSetSocket failed");
        return -1;
    }

    _init_done = M2MConnectionSecurityPimpl::INIT_DONE;

    pal_sslDebugging(0);
    tr_debug("M2MConnectionSecurityPimpl::init - out");
    return 0;
}

int M2MConnectionSecurityPimpl::start_handshake()
{
    tr_debug("M2MConnectionSecurityPimpl::start_handshake");

    palStatus_t ret;

    ret = pal_handShake(_ssl, _conf);

    if(ret == PAL_ERR_TLS_WANT_READ || ret == PAL_ERR_TLS_WANT_WRITE || ret == PAL_ERR_TIMEOUT_EXPIRED){
        return M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }

    if(ret != PAL_SUCCESS){ //We loose the original error here!
        return -1;
    }

    if(PAL_SUCCESS != pal_sslGetVerifyResult( _ssl )){
        return -1;
    }

    return ret;
}

int M2MConnectionSecurityPimpl::connect(M2MConnectionHandler* connHandler)
{
    tr_debug("M2MConnectionSecurityPimpl::connect");
    int ret = -1;

    if(M2MConnectionSecurityPimpl::INIT_DONE != _init_done){
        return ret;
    }

    ret = start_handshake();
    tr_debug("M2MConnectionSecurityPimpl::connect - handshake ret: %d", ret);
    return ret;
}


int M2MConnectionSecurityPimpl::send_message(unsigned char *message, int len)
{
    tr_debug("M2MConnectionSecurityPimpl::send_message");
    int ret = -1;
    palStatus_t return_value;
    uint32_t len_write;

    if(M2MConnectionSecurityPimpl::INIT_DONE != _init_done){
        return ret;
    }


    if(PAL_SUCCESS == (return_value = pal_sslWrite(_ssl, message, len, &len_write))){
        ret = (int)len_write;
    }

    else if(return_value == PAL_ERR_TLS_WANT_READ || return_value == PAL_ERR_TLS_WANT_WRITE || return_value == PAL_ERR_TIMEOUT_EXPIRED){
        ret = M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }

    tr_debug("M2MConnectionSecurityPimpl::send_message - ret: %d", ret);
    return ret; //bytes written
}

int M2MConnectionSecurityPimpl::read(unsigned char* buffer, uint16_t len)
{
    int ret = -1;
    palStatus_t return_value;
    uint32_t len_read;

    if(M2MConnectionSecurityPimpl::INIT_DONE != _init_done){
        tr_error("M2MConnectionSecurityPimpl::read - init not done!");
        return ret;
    }

    if(PAL_SUCCESS == (return_value = pal_sslRead(_ssl, buffer, len, &len_read))){
        ret = (int)len_read;
    }

    else if(return_value == PAL_ERR_TLS_WANT_READ || return_value == PAL_ERR_TLS_WANT_WRITE || return_value == PAL_ERR_TIMEOUT_EXPIRED){
        ret = M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }

    return ret;
}

void M2MConnectionSecurityPimpl::set_random_number_callback(random_number_cb callback)
{
    (void)callback;
}

void M2MConnectionSecurityPimpl::set_entropy_callback(entropy_cb callback)
{

    _entropy = callback;

}

void M2MConnectionSecurityPimpl::set_socket(palSocket_t socket, palSocketAddress_t *address)
{
    tls_socket.socket = socket;
    tls_socket.socketAddress = address;
    tls_socket.addressLength = sizeof(palSocketAddress_t);

    if(_sec_mode == M2MConnectionSecurity::TLS){
        tls_socket.transportationMode = PAL_TLS_MODE;
    }
    else{
        tls_socket.transportationMode = PAL_DTLS_MODE;
    }
}

bool M2MConnectionSecurityPimpl::certificate_parse_valid_time(const char *certificate, uint32_t certificate_len, time_t *valid_from, time_t *valid_to)
{
    palX509Handle_t cert;
    size_t len;
    palStatus_t ret;

    tr_debug("certificate_validfrom_time");

    if(PAL_SUCCESS != (ret = pal_x509Initiate(&cert))) {
        tr_error("certificate_validfrom_time - cert init failed: %u", (int)ret);
        pal_x509Free(&cert);
        return false;
    }
    if(PAL_SUCCESS != (ret = pal_x509CertParse(cert, (const unsigned char*)certificate, certificate_len))) {
        tr_error("certificate_validfrom_time - cert parse failed: %u", (int)ret);
        pal_x509Free(&cert);
        return false;
    }
    if(PAL_SUCCESS != (ret = pal_x509CertGetAttribute(cert, PAL_X509_VALID_FROM, valid_from, sizeof(time_t), &len))) {
        tr_error("certificate_validfrom_time - cert attr get failed: %u", (int)ret);
        pal_x509Free(&cert);
        return false;
    }
    if(PAL_SUCCESS != (ret = pal_x509CertGetAttribute(cert, PAL_X509_VALID_TO, valid_to, sizeof(time_t), &len))) {
        tr_error("certificate_validfrom_time - cert attr get failed: %u", (int)ret);
        pal_x509Free(&cert);
        return false;
    }

    pal_x509Free(&cert);
    return true;
}

bool M2MConnectionSecurityPimpl::check_security_object_validity(const M2MSecurity *security) {
    // Get time from device object
    M2MDevice *device = M2MInterfaceFactory::create_device();
    const uint8_t *certificate = NULL;
    int64_t device_time = 0;
    uint32_t cert_len = 0;

    if (device == NULL || security == NULL || device->is_resource_present(M2MDevice::CurrentTime) == false) {
        tr_error("No time from device object or security object available, fail connector registration %p, %p, %d\n", device, security, device->is_resource_present(M2MDevice::CurrentTime));
        return false;
    }

    // Get time from device object
    device_time = device->resource_value_int(M2MDevice::CurrentTime, 0);

    tr_info("Checking client certificate validity");

    // Get client certificate
    cert_len = security->resource_value_buffer(M2MSecurity::PublicKey, certificate);
    if (cert_len == 0 || certificate == NULL) {
        tr_error("No certificate to check, return fail");
        return false;
    }

    if (!check_certificate_validity(certificate, cert_len, device_time)) {
        tr_error("Client certificate not valid!");
        return false;
    }

    tr_info("Checking server certificate validity");

    // Get server certificate
    cert_len = security->resource_value_buffer(M2MSecurity::ServerPublicKey, certificate);
    if (cert_len == 0 || certificate == NULL) {
        tr_error("No certificate to check, return fail");
        return false;
    }

    if (!check_certificate_validity(certificate, cert_len, device_time)) {
        tr_error("Server certificate not valid!");
        return false;
    }

    return true;
}

bool M2MConnectionSecurityPimpl::check_certificate_validity(const uint8_t *cert, const uint32_t cert_len, const int64_t device_time)
{

    // Get the validFrom and validTo fields from certificate
    time_t server_validfrom = 0;
    time_t server_validto = 0;
    if(!certificate_parse_valid_time((const char*)cert, cert_len, &server_validfrom, &server_validto)) {
        tr_error("Certificate time parsing failed");
        return false;
    }

    tr_debug("M2MConnectionSecurityPimpl::check_certificate_validity - valid from: %" PRIu32, server_validfrom);
    tr_debug("M2MConnectionSecurityPimpl::check_certificate_validity - valid to: %" PRIu32, server_validto);
    tr_debug("M2MConnectionSecurityPimpl::check_certificate_validity - device time: %" PRId64, device_time);

    if (device_time < (uint32_t)server_validfrom || device_time > (uint32_t)server_validto) {
        tr_error("Invalid certificate validity or device time outside of certificate validity period!");
        return false;
    }

    return true;
}

