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
extern "C"{
#include "pal_TLS.h"
}
#include "m2mdevice.h"
#include "m2minterfacefactory.h"
#include <string.h>

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#define TRACE_GROUP "mClt"

#ifdef MBED_CLOUD_CLIENT_CUSTOM_MBEDTLS_ENTROPY
static entropy_cb entropy_callback;
#endif

M2MConnectionSecurityPimpl::M2MConnectionSecurityPimpl(M2MConnectionSecurity::SecurityMode mode)
    :_init_done(M2MConnectionSecurityPimpl::INIT_NOT_STARTED),
     _conf(0),
     _ssl(0),
     _sec_mode(mode)
{
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

#ifdef MBED_CLOUD_CLIENT_CUSTOM_MBEDTLS_ENTROPY

    if(entropy_callback.entropy_source_ptr) {
        if( mbedtls_entropy_add_source( &_entropy, entropy_callback.entropy_source_ptr,
                                        entropy_callback.p_source,entropy_callback.threshold,
                                        entropy_callback.strong ) < 0 ){
            return -1;
        }
    }

#endif

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
            tr_error("M2MConnectionSecurityPimpl::init - M2MServer certificate invalid!");
            return -1;
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
#ifdef MBED_CLOUD_CLIENT_CUSTOM_MBEDTLS_ENTROPY
    entropy_callback = callback;
#endif
    (void)callback;
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

uint32_t M2MConnectionSecurityPimpl::certificate_expiration_time(const char *certificate, uint32_t cert_len)
{
    tr_debug("certificate_expiration_time");
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    uint32_t epoch_time = 0;

    int ret = mbedtls_x509_crt_parse(&cert, (const unsigned char*)certificate,
                           cert_len + 1);
    if(ret == 0) {
        mbedtls_x509_time time = cert.valid_to;
        struct tm time_struct;
        memset(&time_struct, 0, sizeof(struct tm));
        time_struct.tm_hour = time.hour;
        time_struct.tm_min = time.min;
        time_struct.tm_mon = time.mon;
        time_struct.tm_sec = time.sec;
        time_struct.tm_year = time.year - 1900;
        time_struct.tm_mday = time.day;
        epoch_time = mktime(&time_struct);
    } else {
        tr_error("certificate_expiration_time - cert parsing failed: %d", ret);
    }
    mbedtls_x509_crt_free(&cert);
    return epoch_time;
}


uint32_t M2MConnectionSecurityPimpl::certificate_validfrom_time(const char *certificate, uint32_t cert_len)
{
    tr_debug("M2MConnectionSecurityPimpl::certificate_validfrom_time");
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    uint32_t epoch_time = 0;

    int ret = mbedtls_x509_crt_parse(&cert, (const unsigned char*)certificate,
                           cert_len + 1);
    if(ret == 0) {
        mbedtls_x509_time time = cert.valid_from;
        struct tm time_struct;
        memset(&time_struct, 0, sizeof(struct tm));
        time_struct.tm_hour = time.hour;
        time_struct.tm_min = time.min;
        time_struct.tm_mon = time.mon;
        time_struct.tm_sec = time.sec;
        time_struct.tm_year = time.year - 1900;
        time_struct.tm_mday = time.day;
        epoch_time = mktime(&time_struct);
    } else {
        tr_error("certificate_validfrom_time - cert parsing failed: %d", ret);
    }
    mbedtls_x509_crt_free(&cert);
    return epoch_time;
}

bool M2MConnectionSecurityPimpl::check_security_object_validity(const M2MSecurity *security) {
    // Get time from device object
    M2MDevice *device = M2MInterfaceFactory::create_device();
    const uint8_t *certificate = NULL;
    int64_t device_time = 0;
    uint32_t cert_len = 0;

    if (device == NULL || security == NULL || device->is_resource_present(M2MDevice::CurrentTime) == false) {
        tr_error("No time from device object or security object available, fail connector registration %p, %p, %d\n", device,security, device->is_resource_present(M2MDevice::CurrentTime));
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
    int64_t server_validfrom = (int64_t)certificate_validfrom_time((const char*)cert, cert_len);
    int64_t server_validto = (int64_t)certificate_expiration_time((const char*)cert, cert_len);

    tr_debug("M2MConnectionSecurityPimpl::check_server_certificate_validity - valid from: %" PRId64, server_validfrom);
    tr_debug("M2MConnectionSecurityPimpl::check_server_certificate_validity - valid to: %" PRId64, server_validto);
    tr_debug("M2MConnectionSecurityPimpl::check_server_certificate_validity - device time: %" PRId64, device_time);

    if (device_time < server_validfrom || device_time > server_validto) {
        tr_error("Device time outside of certificate validity period!");
        return false;
    }

    return true;
}
