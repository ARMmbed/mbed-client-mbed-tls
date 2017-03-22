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
#include "CppUTest/TestHarness.h"
#include "test_m2mconnectionsecuritypimpl_mbedtls.h"
#include "m2mtimerobserver.h"
#include "m2msecurity.h"
#include "m2mdevice.h"
#include "m2minterfacefactory.h"
#include "m2msecurity_stub.h"
#include "mbedtls_stub.h"
#include "mbed-client/m2mconnectionhandler.h"
#include "m2mtimer_stub.h"
#include "pal_tls_stub.h"
#include "pal_crypto_stub.h"
#include "m2mdevice_stub.h"

uint32_t get_random_number(void)
{
    return time(NULL);
}

entropy_cb ent_cb;

int ent_poll( void *, unsigned char *output, size_t len,
                           size_t *olen )
{
    for(uint16_t i=0; i < len; i++){
        srand(time(NULL));
        output[i] = rand() % 256;
    }
    *olen = len;

    return( 0 );
}

class TestObserver : public M2MConnectionObserver {

public:
    TestObserver(){}
    void data_available(uint8_t*,
                        uint16_t,
                        const M2MConnectionObserver::SocketAddress &){}

    void socket_error(uint8_t error_code, bool retry = true){}

    void address_ready(const M2MConnectionObserver::SocketAddress &,
                       M2MConnectionObserver::ServerType,
                       const uint16_t){}

    void data_sent(){}
};

Test_M2MConnectionSecurityPimpl::Test_M2MConnectionSecurityPimpl()
{
    mbedtls_stub::clear();
    m2msecurity_stub::clear();
}

Test_M2MConnectionSecurityPimpl::~Test_M2MConnectionSecurityPimpl()
{
}

void Test_M2MConnectionSecurityPimpl::test_constructor()
{
    M2MConnectionSecurityPimpl impl = M2MConnectionSecurityPimpl(M2MConnectionSecurity::TLS);
}

void Test_M2MConnectionSecurityPimpl::test_destructor()
{
    M2MConnectionSecurityPimpl* impl = new M2MConnectionSecurityPimpl(M2MConnectionSecurity::TLS);
    impl->_init_done = M2MConnectionSecurityPimpl::INIT_DONE;
    delete impl;
    //Memory leak detector will report an error if leaks
}

void Test_M2MConnectionSecurityPimpl::test_reset()
{
    M2MConnectionSecurityPimpl impl = M2MConnectionSecurityPimpl(M2MConnectionSecurity::TLS);
    impl._init_done = M2MConnectionSecurityPimpl::INIT_DONE;
    impl.reset();
    CHECK(impl._init_done == false);
}

void Test_M2MConnectionSecurityPimpl::test_init()
{
    M2MConnectionSecurityPimpl impl = M2MConnectionSecurityPimpl(M2MConnectionSecurity::TLS);
    CHECK( -1 == impl.init(NULL) );

    m2msecurity_stub::sec_mode = M2MSecurity::Certificate;
    M2MSecurity* sec = new M2MSecurity(M2MSecurity::Bootstrap);

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::change_status_count = 0;
    CHECK( !impl.init(sec) );

    pal_tls_stub::status = PAL_ERR_GENERIC_FAILURE;
    CHECK( impl.init(sec) );

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::new_status = PAL_ERR_GENERIC_FAILURE;
    pal_tls_stub::change_status_count = 1;
    CHECK( impl.init(sec) );

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::new_status = PAL_ERR_GENERIC_FAILURE;
    pal_tls_stub::change_status_count = 2;
    CHECK( impl.init(sec) );

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::new_status = PAL_ERR_GENERIC_FAILURE;
    pal_tls_stub::change_status_count = 3;
    CHECK( impl.init(sec) );

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::new_status = PAL_ERR_GENERIC_FAILURE;
    pal_tls_stub::change_status_count = 4;
    CHECK( impl.init(sec) );

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::new_status = PAL_ERR_GENERIC_FAILURE;
    pal_tls_stub::change_status_count = 5;
    CHECK( impl.init(sec) );

    m2msecurity_stub::sec_mode = M2MSecurity::Psk;

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::new_status = PAL_ERR_GENERIC_FAILURE;
    pal_tls_stub::change_status_count = 2;
    CHECK( impl.init(sec) );

    m2msecurity_stub::sec_mode = 123;

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::change_status_count = 0;
    CHECK( impl.init(sec) );

    m2msecurity_stub::sec_mode = M2MSecurity::Psk;

    impl._sec_mode = M2MConnectionSecurity::DTLS;

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::change_status_count = 0;
    CHECK( !impl.init(sec) );

    delete sec;
    mbedtls_stub::clear();
}

void Test_M2MConnectionSecurityPimpl::test_connect()
{
    M2MConnectionSecurityPimpl impl = M2MConnectionSecurityPimpl(M2MConnectionSecurity::TLS);

    impl._init_done = 0;
    CHECK( -1 == impl.connect(NULL));

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::change_status_count = 0;
    impl._init_done = M2MConnectionSecurityPimpl::INIT_DONE;
    CHECK(!impl.connect(NULL));

    pal_tls_stub::status = PAL_ERR_TIMEOUT_EXPIRED;
    pal_tls_stub::change_status_count = 0;
    impl._init_done = M2MConnectionSecurityPimpl::INIT_DONE;
    CHECK(M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ == impl.connect(NULL));

    pal_tls_stub::status = PAL_ERR_GENERIC_FAILURE;
    pal_tls_stub::change_status_count = 0;
    impl._init_done = M2MConnectionSecurityPimpl::INIT_DONE;
    CHECK(-1 == impl.connect(NULL));

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::new_status = PAL_ERR_GENERIC_FAILURE;
    pal_tls_stub::change_status_count = 1;
    impl._init_done = M2MConnectionSecurityPimpl::INIT_DONE;
    CHECK(-1 == impl.connect(NULL));

}

void Test_M2MConnectionSecurityPimpl::test_send_message()
{
    M2MConnectionSecurityPimpl impl = M2MConnectionSecurityPimpl(M2MConnectionSecurity::TLS);
    unsigned char msg[6] = "hello";

    CHECK( -1 == impl.send_message(msg, 5) );

    pal_tls_stub::status = PAL_ERR_TIMEOUT_EXPIRED;
    pal_tls_stub::change_status_count = 0;
    impl._init_done = M2MConnectionSecurityPimpl::INIT_DONE;
    CHECK(M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ == impl.send_message(msg, 5));

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::change_status_count = 0;
    impl._init_done = M2MConnectionSecurityPimpl::INIT_DONE;
    CHECK(0 < impl.send_message(msg, 5));

}

void Test_M2MConnectionSecurityPimpl::test_read()

{
    M2MConnectionSecurityPimpl impl = M2MConnectionSecurityPimpl(M2MConnectionSecurity::TLS);
    unsigned char msg[50];
    CHECK( -1 == impl.read(msg, 49));

    pal_tls_stub::status = PAL_ERR_TIMEOUT_EXPIRED;
    pal_tls_stub::change_status_count = 0;
    impl._init_done = M2MConnectionSecurityPimpl::INIT_DONE;
    CHECK(M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ == impl.read(msg, 49));

    pal_tls_stub::status = PAL_SUCCESS;
    pal_tls_stub::change_status_count = 0;
    impl._init_done = M2MConnectionSecurityPimpl::INIT_DONE;
    CHECK(0 < impl.read(msg, 49));
}

void Test_M2MConnectionSecurityPimpl::test_set_random_number_callback()
{
    M2MConnectionSecurityPimpl impl = M2MConnectionSecurityPimpl(M2MConnectionSecurity::TLS);
    random_number_cb cb(&test_random_callback);
    impl.set_random_number_callback(cb);
}

void Test_M2MConnectionSecurityPimpl::test_set_entropy_callback()
{
    M2MConnectionSecurityPimpl impl = M2MConnectionSecurityPimpl(M2MConnectionSecurity::TLS);
    impl.set_entropy_callback(ent_cb);
}

uint32_t test_random_callback()
{
    return 1;
}

void Test_M2MConnectionSecurityPimpl::test_set_socket()
{
    M2MConnectionSecurityPimpl impl = M2MConnectionSecurityPimpl(M2MConnectionSecurity::TLS);
    impl.set_socket(0, NULL);
    impl._sec_mode = M2MConnectionSecurity::DTLS;
    impl.set_socket(0, NULL);
}

void Test_M2MConnectionSecurityPimpl::test_certificate_parse_valid_time()
{
    M2MConnectionSecurityPimpl impl = M2MConnectionSecurityPimpl(M2MConnectionSecurity::TLS);

    pal_crypto_stub::status = PAL_SUCCESS;
    pal_crypto_stub::change_status_count = 0;
    CHECK(impl.certificate_parse_valid_time("", NULL, NULL));

    pal_crypto_stub::status = PAL_ERR_GENERIC_FAILURE;

    CHECK(!impl.certificate_parse_valid_time("", NULL, NULL));

    pal_crypto_stub::status = PAL_SUCCESS;
    pal_crypto_stub::new_status = PAL_ERR_GENERIC_FAILURE;
    pal_crypto_stub::change_status_count = 1;
    CHECK(!impl.certificate_parse_valid_time("", NULL, NULL));

    pal_crypto_stub::status = PAL_SUCCESS;
    pal_crypto_stub::new_status = PAL_ERR_GENERIC_FAILURE;
    pal_crypto_stub::change_status_count = 2;
    CHECK(!impl.certificate_parse_valid_time("", NULL, NULL));

    pal_crypto_stub::status = PAL_SUCCESS;
    pal_crypto_stub::new_status = PAL_ERR_GENERIC_FAILURE;
    pal_crypto_stub::change_status_count = 3;
    CHECK(!impl.certificate_parse_valid_time("", NULL, NULL));

}

void Test_M2MConnectionSecurityPimpl::test_check_server_certificate_validity()
{
    M2MSecurity security(M2MSecurity::Bootstrap);
    M2MConnectionSecurityPimpl impl = M2MConnectionSecurityPimpl(M2MConnectionSecurity::TLS);

    CHECK(!impl.check_server_certificate_validity(NULL));

    m2mdevice_stub::bool_value = true;
    CHECK(!impl.check_server_certificate_validity(&security));

    m2mdevice_stub::int_value = 1;
    m2msecurity_stub::has_value = true;
    CHECK(!impl.check_server_certificate_validity(&security));

    m2mdevice_stub::int_value = 0;
    CHECK(impl.check_server_certificate_validity(&security));

    pal_crypto_stub::status = PAL_ERR_GENERIC_FAILURE;
    CHECK(!impl.check_server_certificate_validity(&security));

    M2MDevice::delete_instance();

}

