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
#include "mbed-client/m2mtimer.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-trace/mbed_trace.h"
#include "mbedtls/debug.h"
extern "C"{
#include "pal_TLS.h"
}
#include <string.h>

#define TRACE_GROUP "mClt"

bool cancelled;


M2MConnectionSecurityPimpl::M2MConnectionSecurityPimpl(M2MConnectionSecurity::SecurityMode mode)
  : _flags(0),
    _sec_mode(mode)
{
    _init_done = false;
    cancelled = true;
}

M2MConnectionSecurityPimpl::~M2MConnectionSecurityPimpl(){
    pal_freeTLS(&_ssl);//todo: should these be checked before freeing somehow?
    pal_tlsConfigurationFree(&_conf);
}

void M2MConnectionSecurityPimpl::reset(){
    _init_done = false;
    cancelled = true;
}

int M2MConnectionSecurityPimpl::init(const M2MSecurity *security)
{
    tr_debug("M2MConnectionSecurityPimpl::init");
    int ret = 0;
    if (security != NULL) {
        const char *pers = "dtls_client";

        palTLSTransportMode_t mode = PAL_DTLS_MODE;
        if( _sec_mode == M2MConnectionSecurity::TLS ){
            mode = PAL_TLS_MODE;
        }

        if(PAL_SUCCESS != pal_initTLSConfiguration(&_conf, mode))
        {
            return (-1);
        }

        if( _sec_mode == M2MConnectionSecurity::DTLS ){
            //pal_setHandShakeTimeOut(_conf, 100); Should we make this call?
        }


        M2MSecurity::SecurityModeType cert_mode =
                (M2MSecurity::SecurityModeType)security->resource_value_int(M2MSecurity::SecurityMode);

        if( cert_mode == M2MSecurity::Certificate ){

            palX509_t owncert;
            palPrivateKey_t privateKey;
            palX509_t caChain;

            owncert.size = security->resource_value_buffer(M2MSecurity::PublicKey, (const uint8_t*&)owncert.buffer);
            privateKey.size = security->resource_value_buffer(M2MSecurity::Secretkey, (const uint8_t*&)privateKey.buffer);
            caChain.size = security->resource_value_buffer(M2MSecurity::ServerPublicKey, (const uint8_t*&)caChain.buffer);

            if(PAL_SUCCESS != pal_setOwnCertAndPrivateKey(_conf, &owncert, &privateKey)){
                ret = -1;
            }

            if(PAL_SUCCESS != pal_setCAChain(_conf, &caChain, NULL)){
                ret = -1;
            }


        } else if ( cert_mode == M2MSecurity::Psk ){

            uint8_t *identity;
            uint32_t identityLen;
            uint8_t *psk;
            uint32_t pskLen;

            pskLen = security->resource_value_buffer(M2MSecurity::PublicKey, psk);
            identityLen = security->resource_value_buffer(M2MSecurity::Secretkey, identity);

            if(PAL_SUCCESS != pal_setPSK(_conf, identity, identityLen, psk, pskLen)){
                ret = -1;
            }


        } else {

            ret = -1;

        }

    }

    if( ret == 0 ){
        if(PAL_SUCCESS != pal_initTLS(_conf, &_ssl))
        {
            ret = -1;
        }
        else
        {
            if(PAL_SUCCESS != pal_tlsSetSocket(_conf, &tls_socket))
            {
                return (-1);
            }
            _init_done = true;
        }
    }
    pal_sslDebugging(0);
    tr_debug("M2MConnectionSecurityPimpl::init - ret %d", ret);
    return ret;
}


int M2MConnectionSecurityPimpl::start_handshake(){
    tr_debug("M2MConnectionSecurityPimpl::start_handshake");

    palStatus_t ret;

    ret = pal_handShake(_ssl, _conf);

    if(ret == PAL_ERR_TLS_WANT_READ || ret == PAL_ERR_TLS_WANT_WRITE){
        return M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }

    if( ret != PAL_SUCCESS ) { //We loose the original error here!
        ret = -1;
    }else {
        if( ( /*_flags*/PAL_SUCCESS != pal_sslGetVerifyResult( _ssl ) ) ) { //TODO: check if flags used somewhere?
            ret = -1;
        }
    }
    tr_debug("M2MConnectionSecurityPimpl::start_handshake - OUT");
    return ret;
}

int M2MConnectionSecurityPimpl::connect(M2MConnectionHandler* connHandler){

    tr_debug("M2MConnectionSecurityPimpl::connect");
    int ret=-1;
    if(!_init_done){
        return ret;
    }

    ret = start_handshake();
    tr_debug("M2MConnectionSecurityPimpl::connect - handshake ret: %d", ret);
    return ret;
}


int M2MConnectionSecurityPimpl::send_message(unsigned char *message, int len){

    tr_debug("M2MConnectionSecurityPimpl::send_message");
    int ret=-1;
    palStatus_t return_value;
    uint32_t len_write;

    if(!_init_done){
        return ret;
    }


    if(PAL_SUCCESS == (return_value = pal_sslWrite(_ssl, message, len, &len_write)))
    {
        ret = (int)len_write;
    }

    if(return_value == PAL_ERR_TLS_WANT_READ || return_value == PAL_ERR_TLS_WANT_WRITE)
    {
        ret = M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }

    tr_debug("M2MConnectionSecurityPimpl::send_message - ret: %d", ret);
    return ret; //bytes written
}

int M2MConnectionSecurityPimpl::read(unsigned char* buffer, uint16_t len){

    int ret =- 1;
    palStatus_t return_value;
    uint32_t len_read;

    if(!_init_done){
        tr_error("M2MConnectionSecurityPimpl::read - init not done!");
        return ret;
    }

    if(PAL_SUCCESS == (return_value = pal_sslRead(_ssl, buffer, len, &len_read)))
    {
        ret = (int)len_read;
    }

    if(return_value == PAL_ERR_TLS_WANT_READ || return_value == PAL_ERR_TLS_WANT_WRITE )
    {
        ret = M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
    }


    return ret;

}


void M2MConnectionSecurityPimpl::set_random_number_callback(random_number_cb callback)
{
//     not used
}
//
void M2MConnectionSecurityPimpl::set_entropy_callback(entropy_cb callback)
{
//    not used
}

void M2MConnectionSecurityPimpl::set_socket(palSocket_t socket, palSocketAddress_t *address)
{

    tls_socket.socket = socket;
    tls_socket.socketAddress = address;
    tls_socket.addressLength = sizeof(palSocketAddress_t);

    if( _sec_mode == M2MConnectionSecurity::TLS ){
        tls_socket.transportationMode = PAL_TLS_MODE;
    }
    else{
        tls_socket.transportationMode = PAL_DTLS_MODE;
    }

}

