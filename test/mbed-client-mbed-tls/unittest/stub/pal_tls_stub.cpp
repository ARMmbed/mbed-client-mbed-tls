/*
 * Copyright (c) 2017 ARM Limited. All rights reserved.
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

#include "pal_tls_stub.h"

palStatus_t pal_tls_stub::status;
palStatus_t pal_tls_stub::new_status;
uint32_t pal_tls_stub::change_status_count;

static palStatus_t get_pal_status(void)
{
    palStatus_t status_to_return;

    status_to_return = pal_tls_stub::status;

    if(pal_tls_stub::change_status_count){

        pal_tls_stub::change_status_count--;

        if(!pal_tls_stub::change_status_count){
            pal_tls_stub::status = pal_tls_stub::new_status;
        }
    }

    return status_to_return;

}

extern "C"{
palStatus_t pal_initTLS(palTLSConfHandle_t palTLSConf, palTLSHandle_t* palTLSHandle)
{
    return get_pal_status();
}

palStatus_t pal_freeTLS(palTLSHandle_t* palTLSHandle)
{
    return get_pal_status();
}

palStatus_t pal_addEntropySource(palEntropySource_f entropyCallback)
{
    return get_pal_status();
}

palStatus_t pal_initTLSConfiguration(palTLSConfHandle_t* palTLSConf, palTLSTransportMode_t transportationMode)
{
    return get_pal_status();
}

palStatus_t pal_tlsConfigurationFree(palTLSConfHandle_t* palTLSConf)
{
    return get_pal_status();
}

palStatus_t pal_setOwnCertAndPrivateKey(palTLSConfHandle_t palTLSConf, palX509_t* ownCert, palPrivateKey_t* privateKey)
{
    return get_pal_status();
}

palStatus_t pal_setCAChain(palTLSConfHandle_t palTLSConf, palX509_t* caChain, palX509CRL_t* caCRL)
{
    return get_pal_status();
}

palStatus_t pal_setPSK(palTLSConfHandle_t palTLSConf, const unsigned char *identity, uint32_t maxIdentityLenInBytes, const unsigned char *psk, uint32_t maxPskLenInBytes)
{
    return get_pal_status();
}

palStatus_t pal_tlsSetSocket(palTLSConfHandle_t palTLSConf, palTLSSocket_t* socket)
{
    return get_pal_status();
}

palStatus_t pal_handShake(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf)
{
    return get_pal_status();
}

palStatus_t pal_setHandShakeTimeOut(palTLSConfHandle_t palTLSConf, uint32_t timeoutInMilliSec)
{
    return get_pal_status();
}

palStatus_t pal_sslGetVerifyResult(palTLSHandle_t palTLSHandle)
{
    return get_pal_status();
}

palStatus_t pal_sslRead(palTLSHandle_t palTLSHandle, void *buffer, uint32_t len, uint32_t* actualLen)
{
    *actualLen = 1;
    return get_pal_status();
}

palStatus_t pal_sslWrite(palTLSHandle_t palTLSHandle, const void *buffer, uint32_t len, uint32_t *bytesWritten)
{
    *bytesWritten = 1;
    return get_pal_status();
}

palStatus_t pal_sslDebugging(uint8_t turnOn)
{
    return get_pal_status();
}
}
