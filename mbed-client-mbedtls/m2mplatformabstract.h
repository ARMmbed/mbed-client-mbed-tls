/*
 * Copyright (c) 2014-2015 ARM Limited. All rights reserved.
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

#ifndef M2M_PLATFORM_ABSTRACT_H__
#define M2M_PLATFORM_ABSTRACT_H__
#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Get random number for the underlying platform.
 * This API needs to be implemented by the application using
 * mbed Client in order to provide randomly generated number
 * based on underlying platform, which will be used internally
 * by mbed Client for SSL handshake mechanism.
 */
extern uint32_t get_random_number(void);
#ifdef __cplusplus
}
#endif
#endif // M2M_PLATFORM_ABSTRACT_H__
