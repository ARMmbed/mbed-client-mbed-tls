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
//CppUTest includes should be after your and system includes
#include "CppUTest/TestHarness.h"
#include "test_m2mconnectionsecuritypimpl_mbedtls.h"


TEST_GROUP(M2MConnectionSecurityPimpl_mbedtls)
{
  Test_M2MConnectionSecurityPimpl* inst;

  void setup()
  {
    inst = new Test_M2MConnectionSecurityPimpl();
  }
  void teardown()
  {
    delete inst;
  }
};

TEST(M2MConnectionSecurityPimpl_mbedtls, Create)
{
    CHECK(inst != NULL);
}

TEST(M2MConnectionSecurityPimpl_mbedtls, test_constructor)
{
    inst->test_constructor();
}

TEST(M2MConnectionSecurityPimpl_mbedtls, test_destructor)
{
    inst->test_destructor();
}

TEST(M2MConnectionSecurityPimpl_mbedtls, test_reset)
{
    inst->test_reset();
}

TEST(M2MConnectionSecurityPimpl_mbedtls, test_init)
{
    inst->test_init();
}

TEST(M2MConnectionSecurityPimpl_mbedtls, test_connect)
{
    inst->test_connect();
}

TEST(M2MConnectionSecurityPimpl_mbedtls, test_send_message)
{
    inst->test_send_message();
}

TEST(M2MConnectionSecurityPimpl_mbedtls, test_read)
{
    inst->test_read();
}

TEST(M2MConnectionSecurityPimpl_mbedtls, test_set_random_number_callback)
{
    inst->test_set_random_number_callback();
}

TEST(M2MConnectionSecurityPimpl_mbedtls, test_set_entropy_callback)
{
    inst->test_set_entropy_callback();
}

TEST(M2MConnectionSecurityPimpl_mbedtls, test_set_socket)
{
    inst->test_set_socket();
}

TEST(M2MConnectionSecurityPimpl_mbedtls, test_certificate_parse_valid_time)
{
    inst->test_certificate_parse_valid_time();
}

TEST(M2MConnectionSecurityPimpl_mbedtls, test_check_server_certificate_validity)
{
    inst->test_check_server_certificate_validity();
}


