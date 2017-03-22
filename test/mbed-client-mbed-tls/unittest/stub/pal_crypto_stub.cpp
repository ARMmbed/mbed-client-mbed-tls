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

#include "pal_crypto_stub.h"

palStatus_t pal_crypto_stub::status;
palStatus_t pal_crypto_stub::new_status;
uint32_t pal_crypto_stub::change_status_count;

static palStatus_t get_pal_status(void)
{
    palStatus_t status_to_return;

    status_to_return = pal_crypto_stub::status;

    if(pal_crypto_stub::change_status_count){

        pal_crypto_stub::change_status_count--;

        if(!pal_crypto_stub::change_status_count){
            pal_crypto_stub::status = pal_crypto_stub::new_status;
        }
    }

    return status_to_return;

}

extern "C"{

palStatus_t pal_initAes(palAesHandle_t *aes)
{
    return get_pal_status();
}

palStatus_t pal_freeAes(palAesHandle_t *aes)
{
    return get_pal_status();
}

palStatus_t pal_setAesKey(palAesHandle_t aes, const unsigned char* key, uint32_t keybits, palAesKeyType_t keyTarget)
{
    return get_pal_status();
}

palStatus_t pal_aesCTR(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16])
{
    return get_pal_status();
}

palStatus_t pal_aesCTRWithZeroOffset(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16])
{
    return get_pal_status();
}

palStatus_t pal_aesECB(palAesHandle_t aes, const unsigned char input[16], unsigned char output[16], palAesMode_t mode)

{
    return get_pal_status();
}

palStatus_t pal_sha256(const unsigned char* input, size_t inLen, unsigned char* output)

{
    return get_pal_status();
}


palStatus_t pal_x509Initiate(palX509Handle_t* x509Cert)

{
    return get_pal_status();
}

palStatus_t pal_x509CertParse(palX509Handle_t x509Cert, const unsigned char* input, size_t inLen)
{
    return get_pal_status();
}

palStatus_t pal_x509CertGetAttribute(palX509Handle_t x509Cert, palX509Attr_t attr, void* output, size_t outLenBytes, size_t* actualOutLenBytes)
{
    return get_pal_status();
}

palStatus_t pal_x509CertVerify(palX509Handle_t x509Cert, palX509Handle_t x509CertChain)
{
    return get_pal_status();
}

palStatus_t pal_x509Free(palX509Handle_t* x509Cert)
{
    return get_pal_status();
}

palStatus_t pal_mdInit(palMDHandle_t* md, palMDType_t mdType)
{
    return get_pal_status();
}

palStatus_t pal_mdUpdate(palMDHandle_t md, const unsigned char* input, size_t inLen)
{
    return get_pal_status();
}

palStatus_t pal_mdGetOutputSize(palMDHandle_t md, size_t* bufferSize)
{
    return get_pal_status();
}

palStatus_t pal_mdFinal(palMDHandle_t md, unsigned char* output)
{
    return get_pal_status();
}

palStatus_t pal_mdFree(palMDHandle_t* md)
{
    return get_pal_status();
}

palStatus_t pal_verifySignature(palX509Handle_t x509, palMDType_t mdType, const unsigned char *hash, size_t hashLen, const unsigned char *sig, size_t sigLen)
{
    return get_pal_status();
}

palStatus_t pal_ASN1GetTag(unsigned char **position, const unsigned char *end, size_t *len, uint8_t tag)
{
    return get_pal_status();
}

palStatus_t pal_CCMInit(palCCMHandle_t* ctx)
{
    return get_pal_status();
}

palStatus_t pal_CCMFree(palCCMHandle_t* ctx)
{
    return get_pal_status();
}

palStatus_t pal_CCMSetKey(palCCMHandle_t ctx, 
						const unsigned char *key, uint32_t keybits, palCipherID_t id)
{
    return get_pal_status();
}

palStatus_t pal_CCMDecrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, 
							unsigned char* iv, size_t ivLen, unsigned char* add, 
							size_t addLen, unsigned char* tag, size_t tagLen, 
							unsigned char* output)
{
    return get_pal_status();
}

palStatus_t pal_CCMEncrypt(palCCMHandle_t ctx, unsigned char* input, 
							size_t inLen, unsigned char* iv, size_t ivLen, 
							unsigned char* add, size_t addLen, unsigned char* output, 
							unsigned char* tag, size_t tagLen)
{
    return get_pal_status();
}

palStatus_t pal_CtrDRBGInit(palCtrDrbgCtxHandle_t* ctx, const void* seed, size_t len)
{
    return get_pal_status();
}

palStatus_t pal_CtrDRBGGenerate(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len)
{
    return get_pal_status();
}


palStatus_t pal_CtrDRBGFree(palCtrDrbgCtxHandle_t* ctx)
{
    return get_pal_status();
}

palStatus_t pal_cipherCMAC(const unsigned char *key, size_t keyLenInBits, const unsigned char *input, size_t inputLenInBytes, unsigned char *output)
{
    return get_pal_status();
}

palStatus_t pal_CMACStart(palCMACHandle_t *ctx, const unsigned char *key, size_t keyLenBits, palCipherID_t cipherID)
{
    return get_pal_status();
}

palStatus_t pal_CMACUpdate(palCMACHandle_t ctx, const unsigned char *input, size_t inLen)
{
    return get_pal_status();
}

palStatus_t pal_CMACFinish(palCMACHandle_t *ctx, unsigned char *output, size_t* outLen)
{
    return get_pal_status();
}

palStatus_t pal_ECCheckKey(palCurveHandle_t grp, palECKeyHandle_t key, uint32_t type, bool *verified)
{
    return get_pal_status();
}

palStatus_t pal_ECKeyNew(palECKeyHandle_t* key)
{
    return get_pal_status();
}

palStatus_t pal_ECKeyFree(palECKeyHandle_t* key)
{
    return get_pal_status();
}

palStatus_t pal_parseECPrivateKeyFromDER(const unsigned char* prvDERKey, size_t keyLen, palECKeyHandle_t key)
{
    return get_pal_status();
}

palStatus_t pal_parseECPublicKeyFromDER(const unsigned char* pubDERKey, size_t keyLen, palECKeyHandle_t key)
{
    return get_pal_status();
}

palStatus_t pal_writePrivateKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize)
{
    return get_pal_status();
}

palStatus_t pal_writePublicKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize)
{
    return get_pal_status();
}

palStatus_t pal_ECKeyGenerateKey(palGroupIndex_t grpID, palECKeyHandle_t key)
{
    return get_pal_status();
}

palStatus_t pal_ECKeyGetCurve(palECKeyHandle_t key, palGroupIndex_t* grpID)
{
    return get_pal_status();
}

palStatus_t pal_ECGroupInitAndLoad(palCurveHandle_t* grp, palGroupIndex_t index)
{
    return get_pal_status();
}

palStatus_t pal_ECGroupFree(palCurveHandle_t* grp)
{
    return get_pal_status();
}

palStatus_t pal_x509CSRInit(palx509CSRHandle_t *x509CSR)
{
    return get_pal_status();
}

palStatus_t pal_x509CSRSetSubject(palx509CSRHandle_t x509CSR, const char* subjectName)
{
    return get_pal_status();
}

palStatus_t pal_x509CSRSetMD(palx509CSRHandle_t x509CSR, palMDType_t mdType)
{
    return get_pal_status();
}

palStatus_t pal_x509CSRSetKey(palx509CSRHandle_t x509CSR, palECKeyHandle_t pubKey, palECKeyHandle_t prvKey)
{
    return get_pal_status();
}

palStatus_t pal_x509CSRSetKeyUsage(palx509CSRHandle_t x509CSR, uint32_t keyUsage)
{
    return get_pal_status();
}

palStatus_t pal_x509CSRSetExtension(palx509CSRHandle_t x509CSR,const char* oid, size_t oidLen, 
									const unsigned char* value, size_t valueLen)
{
    return get_pal_status();
}

palStatus_t pal_x509CSRWriteDER(palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerLen)
{
    return get_pal_status();
}

palStatus_t pal_x509CSRFree(palx509CSRHandle_t *x509CSR)
{
    return get_pal_status();
}

palStatus_t pal_ECDHComputeKey(const palCurveHandle_t grp, const palECKeyHandle_t peerPublicKey, 
								const palECKeyHandle_t privateKey, palECKeyHandle_t outKey)
{
    return get_pal_status();
}

palStatus_t pal_ECDSASign(palCurveHandle_t grp, palMDType_t mdType, palECKeyHandle_t prvKey, unsigned char* dgst, 
									uint32_t dgstLen, unsigned char *sig, size_t *sigLen)
{
    return get_pal_status();
}

palStatus_t pal_ECDSAVerify(palECKeyHandle_t pubKey, unsigned char* dgst, uint32_t dgstLen, unsigned char* sig, size_t sigLen, bool* verified)
{
    return get_pal_status();
}



}




