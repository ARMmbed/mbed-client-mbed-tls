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

#ifndef __M2M_CONNECTION_SECURITY_PIMPL_H__
#define __M2M_CONNECTION_SECURITY_PIMPL_H__

#include "mbed-client/m2mconnectionsecurity.h"
#include "mbed-client/m2mtimerobserver.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2msecurity.h"
extern "C"{
#include "pal_TLS.h"
}

class M2MTimer;

//TODO: Should we let application to select these or not??
//const static int PSK_SUITES[] = {
//    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
//    MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8,
//    MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8,
//    0
//};


/**
 * @brief The M2MConnectionSecurityPimpl class
 */
class M2MConnectionSecurityPimpl{

private:

    // Prevents the use of assignment operator by accident.
    M2MConnectionSecurityPimpl& operator=( const M2MConnectionSecurityPimpl& /*other*/ );
    // Prevents the use of copy constructor by accident
    M2MConnectionSecurityPimpl( const M2MConnectionSecurityPimpl& /*other*/ );

public:

    /**
     * @brief Constructor
     */
    M2MConnectionSecurityPimpl(M2MConnectionSecurity::SecurityMode mode);

    /**
    * @brief Destructor
    */
    virtual ~M2MConnectionSecurityPimpl();

    /**
     * \brief Resets the socket connection states.
     */
    void reset();

    /**
     * \brief Initiatlizes the socket connection states.
     */
    int init(const M2MSecurity *security);

    /**
     * \brief Connects the client to the server.
     * \param connHandler The ConnectionHandler object that maintains the socket.
     * \return Returns the state of the connection. Successful or not.
     *         If 2MConnectionHandler::CONNECTION_ERROR_WANTS_READ is returned
     *         this function must be called again later to continue the handshake.
     */
    int connect(M2MConnectionHandler* connHandler);

    /**
     * \brief Sends data to the server.
     * \param message The data to be sent.
     * \param len The length of the data.
     * @return Indicates whether the data is sent successfully or not.
     */
    int send_message(unsigned char *message, int len);

    /**
     * \brief Reads the data received from the server.
     * \param message The data to be read.
     * \param len The length of the data.
     * \return Indicates whether the data is read successfully or not.
     */
    int read(unsigned char* buffer, uint16_t len);

    /**
     * No longer used for anything.
     */
    void set_random_number_callback(random_number_cb callback);

    /**
     * No longer used for anything.
     */
    void set_entropy_callback(entropy_cb callback);

    /**
     * \brief Set socket information for this secure connection.
     * \param socket Socket used with this TLS session.
     * \param address Pointer to the address of the server.
     * \return Indicates whether the data is read successfully or not.
     */
    void set_socket(palSocket_t socket, palSocketAddress_t *address);

private:

    int start_handshake();

private:

    bool                        _init_done;
    palTLSConfHandle_t          _conf;
    palTLSHandle_t              _ssl;
    palTLSSocket_t              _socket;
    uint32_t                    _flags;
    M2MConnectionSecurity::SecurityMode _sec_mode;
    palTLSSocket_t tls_socket;

    friend class Test_M2MConnectionSecurityPimpl;
};

#endif //__M2M_CONNECTION_SECURITY_PIMPL_H__
