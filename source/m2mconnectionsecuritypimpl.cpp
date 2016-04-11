/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
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
#include <string.h>

#define TRACE_GROUP "mClt"

void mbedtls_timing_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms );
int mbedtls_timing_get_delay( void *data );
int entropy_poll( void *data, unsigned char *output, size_t len, size_t *olen );
//Point these back to M2MConnectionHandler!!!
int f_send( void *ctx, const unsigned char *buf, size_t len );
int f_recv(void *ctx, unsigned char *buf, size_t len);
int f_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t some);

bool cancelled;

M2MConnectionSecurityPimpl::M2MConnectionSecurityPimpl(M2MConnectionSecurity::SecurityMode mode)
  : _flags(0),
    _sec_mode(mode),
    _is_blocking(false),
    _retry_count(0),
    _srv_public_key(NULL),
    _srv_public_key_size(0),
    _public_key(NULL),
    _public_key_size(0),
    _sec_key(NULL),
    _sec_key_size(0),
    _cert_mode(M2MSecurity::SecurityNotSet)
{
    _init_done = false;
    cancelled = true;
    _timer = new M2MTimer(*this);
    mbedtls_ssl_init( &_ssl );
    mbedtls_ssl_config_init( &_conf );
    mbedtls_x509_crt_init( &_cacert );
    mbedtls_x509_crt_init(&_owncert);
    mbedtls_pk_init(&_pkey);
    mbedtls_ctr_drbg_init( &_ctr_drbg );
    mbedtls_entropy_init( &_entropy );
}

M2MConnectionSecurityPimpl::~M2MConnectionSecurityPimpl(){
    mbedtls_ssl_config_free(&_conf);
    mbedtls_ssl_free(&_ssl);
    mbedtls_x509_crt_free(&_cacert);
    mbedtls_x509_crt_free(&_owncert);
    mbedtls_pk_free(&_pkey);
    mbedtls_ctr_drbg_free( &_ctr_drbg );
    mbedtls_entropy_free( &_entropy );
    delete _timer;
    free_keys();
}

void M2MConnectionSecurityPimpl::free_keys()
{
    if (_srv_public_key) {
        free(_srv_public_key);
        _srv_public_key = NULL;
    }
    if (_public_key) {
        free(_public_key);
        _public_key = NULL;
    }
    if (_sec_key) {
        free(_sec_key);
        _sec_key = NULL;
    }
    _srv_public_key_size = 0;
    _public_key_size = 0;
    _sec_key_size = 0;
}

void M2MConnectionSecurityPimpl::timer_expired(M2MTimerObserver::Type type){
    tr_debug("M2MConnectionSecurityPimpl::timer_expired");
    if(type == M2MTimerObserver::Dtls && !cancelled){
        int error = continue_connecting();
        if(MBEDTLS_ERR_SSL_TIMEOUT == error) {
            tr_debug("M2MConnectionSecurityPimpl::timer_expired - DTLS timeout");
            if(_ssl.p_bio) {
                M2MConnectionHandler* ptr = (M2MConnectionHandler*)_ssl.p_bio;
                ptr->handle_connection_error(int(M2MInterface::Timeout));
            }
        }
    } else {
        tr_debug("M2MConnectionSecurityPimpl::timer_expired connection error");
        if(_ssl.p_bio) {
            M2MConnectionHandler* ptr = (M2MConnectionHandler*)_ssl.p_bio;
            ptr->handle_connection_error(int(M2MInterface::Timeout));
        }
    }
}

void M2MConnectionSecurityPimpl::reset(){
    _init_done = false;
    cancelled = true;
    mbedtls_ssl_config_free(&_conf);
    mbedtls_ssl_free(&_ssl);
    mbedtls_x509_crt_free(&_cacert);
    mbedtls_x509_crt_free(&_owncert);
    mbedtls_pk_free(&_pkey);
    mbedtls_ctr_drbg_free( &_ctr_drbg );
    mbedtls_entropy_free( &_entropy );
    _timer->stop_timer();
}

int M2MConnectionSecurityPimpl::read_security_keys(const M2MSecurity *security)
{
    tr_debug("M2MConnectionSecurityPimpl::read_security_keys");
    free_keys();
    if (security != NULL) {
        _cert_mode =  (M2MSecurity::SecurityModeType)security->resource_value_int(M2MSecurity::SecurityMode);
        _srv_public_key_size = security->resource_value_buffer(M2MSecurity::ServerPublicKey, _srv_public_key);
        _public_key_size = security->resource_value_buffer(M2MSecurity::PublicKey, _public_key);
        _sec_key_size = security->resource_value_buffer(M2MSecurity::Secretkey, _sec_key);
        if( _srv_public_key == NULL || _public_key == NULL || _sec_key == NULL ||
            _srv_public_key_size == 0 || _public_key_size == 0 || _sec_key_size == 0 ){
            return -1;
        }
    } else {
        return -1;
    }
    tr_debug("M2MConnectionSecurityPimpl::read_security_keys - OUT");
}
int M2MConnectionSecurityPimpl::init_ssl()
{
    tr_debug("M2MConnectionSecurityPimpl::init_ssl");
    int ret = -1;
    const char *pers = "dtls_client";
    mbedtls_ssl_init( &_ssl );
    mbedtls_ssl_config_init( &_conf );
    mbedtls_x509_crt_init( &_cacert );
    mbedtls_x509_crt_init(&_owncert);
    mbedtls_pk_init(&_pkey);
    mbedtls_ctr_drbg_init( &_ctr_drbg );
    mbedtls_entropy_init( &_entropy );

    if( mbedtls_entropy_add_source( &_entropy, entropy_poll, NULL,
                                128, 0 ) < 0 ){
        return -1;
    }

    if( ( ret = mbedtls_ctr_drbg_seed( &_ctr_drbg, mbedtls_entropy_func, &_entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 ) {
        return -1;
    }

    int mode = MBEDTLS_SSL_TRANSPORT_DATAGRAM;
    if( _sec_mode == M2MConnectionSecurity::TLS ){
        mode = MBEDTLS_SSL_TRANSPORT_STREAM;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &_conf,
                       MBEDTLS_SSL_IS_CLIENT,
                       mode, 0 ) ) != 0 ) {
        return -1;
    }

    if( _cert_mode == M2MSecurity::Certificate ){
        ret = mbedtls_x509_crt_parse( &_cacert, (const unsigned char *) _srv_public_key,
                                  _srv_public_key_size );
        if( ret < 0 ) {
            return -1;
        }

        ret = mbedtls_x509_crt_parse( &_owncert, (const unsigned char *) _public_key,
                                  _public_key_size );
        if( ret < 0 ) {
            return -1;
        }

        ret = mbedtls_pk_parse_key(&_pkey, (const unsigned char *) _sec_key,
                                   _sec_key_size, NULL, 0);
        if( ret < 0 ) {
            return -1;
        }
        mbedtls_ssl_conf_own_cert(&_conf, &_owncert, &_pkey);
        mbedtls_ssl_conf_authmode( &_conf, MBEDTLS_SSL_VERIFY_REQUIRED );
        mbedtls_ssl_conf_ca_chain( &_conf, &_cacert, NULL );
    }else if(_cert_mode == M2MSecurity::Psk ){
        ret = mbedtls_ssl_conf_psk(&_conf, _sec_key, _sec_key_size, _public_key, _public_key_size);
        mbedtls_ssl_conf_ciphersuites(&_conf, PSK_SUITES);
    }else{
        ret = -1;
    }
    tr_debug("M2MConnectionSecurityPimpl::init_ssl - ret %d", ret);
    return ret;
}

int M2MConnectionSecurityPimpl::init(const M2MSecurity *security){
    tr_debug("M2MConnectionSecurityPimpl::init");
    int ret = -1;
    if (read_security_keys(security)) {
        ret = init_ssl();
        if( ret >= 0 ){
            _init_done = true;
        }
    }
    free_keys();
    tr_debug("M2MConnectionSecurityPimpl::init - OUT");
    return ret;
}

int M2MConnectionSecurityPimpl::start_handshake(){
    tr_error("M2MConnectionSecurityPimpl::start_handshake");
    int ret = -1;
    int retry_count = 0;
    do
    {
       ret = mbedtls_ssl_handshake( &_ssl );
       if (ret == -1) {
           retry_count++;
           tr_debug("M2MConnectionSecurityPimpl::start_handshake - try again");
       }
    }
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
           (ret == -1 && retry_count <= RETRY_COUNT));

    if( ret != 0 ) {
        ret = -1;
    }else {
        if( ( _flags = mbedtls_ssl_get_verify_result( &_ssl ) ) != 0 ) {
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

    _is_blocking = true;
    mbedtls_ssl_conf_rng( &_conf, mbedtls_ctr_drbg_random, &_ctr_drbg );

    if( ( ret = mbedtls_ssl_setup( &_ssl, &_conf ) ) != 0 ) {
       return -1;
    }

    mbedtls_ssl_set_bio( &_ssl, connHandler,
                        f_send, f_recv, f_recv_timeout );

    mbedtls_ssl_set_timer_cb( &_ssl, _timer, mbedtls_timing_set_delay,
                              mbedtls_timing_get_delay );

    ret = start_handshake();
    _timer->stop_timer();
    tr_debug("M2MConnectionSecurityPimpl::connect - handshake ret: %d, ssl state: %d", ret, _ssl.state);
    return ret;
}

int M2MConnectionSecurityPimpl::start_connecting_non_blocking(M2MConnectionHandler* connHandler)
{
    tr_debug("M2MConnectionSecurityPimpl::start_connecting_non_blocking");
    int ret=-1;
    if(!_init_done){
        return ret;
    }

    _is_blocking = false;
    int mode = MBEDTLS_SSL_TRANSPORT_DATAGRAM;
    if( _sec_mode == M2MConnectionSecurity::TLS ){
        mode = MBEDTLS_SSL_TRANSPORT_STREAM;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &_conf,
                       MBEDTLS_SSL_IS_CLIENT,
                       mode, 0 ) ) != 0 )
    {
        return -1;
    }

    // This is for non-blocking sockets total timeout is 1+2+4+8+16+29=60 seconds
    mbedtls_ssl_conf_handshake_timeout( &_conf, 10000, 29000 );
    mbedtls_ssl_conf_rng( &_conf, mbedtls_ctr_drbg_random, &_ctr_drbg );

    if( ( ret = mbedtls_ssl_setup( &_ssl, &_conf ) ) != 0 )
    {
       return -1;
    }

    mbedtls_ssl_set_bio( &_ssl, connHandler,
                        f_send, f_recv, f_recv_timeout );

    mbedtls_ssl_set_timer_cb( &_ssl, _timer, mbedtls_timing_set_delay,
                                            mbedtls_timing_get_delay );

    ret = mbedtls_ssl_handshake_step( &_ssl );
    if( ret == 0 ){
        ret = mbedtls_ssl_handshake_step( &_ssl );
    }

    if( ret >= 0){
        ret = 1;
    } else {
        ret = -1;
    }
    tr_debug("M2MConnectionSecurityPimpl::start_connecting_non_blocking - handshake ret: %d, ssl state: %d", ret, _ssl.state);
    return ret;
}

int M2MConnectionSecurityPimpl::continue_connecting()
{
    tr_debug("M2MConnectionSecurityPimpl::continue_connecting");
    int ret=-1;
    while( ret != M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ){
        ret = mbedtls_ssl_handshake( &_ssl );
        if( MBEDTLS_ERR_SSL_WANT_READ == ret ){
            ret = M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ;
        }
        if(MBEDTLS_ERR_SSL_TIMEOUT == ret ||
           MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO == ret ||
           MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE == ret ||
           MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST == ret ||
           MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE == ret ||
           MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE == ret ||
           MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC == ret ||
           MBEDTLS_ERR_SSL_BAD_HS_FINISHED == ret) {
            return MBEDTLS_ERR_SSL_TIMEOUT;
        }
        if( _ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER ){
            return 0;
        }
    }
    tr_debug("M2MConnectionSecurityPimpl::continue_connecting, ret: %d", ret);
    return ret;
}

int M2MConnectionSecurityPimpl::send_message(unsigned char *message, int len){
    tr_debug("M2MConnectionSecurityPimpl::send_message");
    int ret=-1;
    if(!_init_done){
        return ret;
    }

    do ret = mbedtls_ssl_write( &_ssl, (unsigned char *) message, len );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    tr_debug("M2MConnectionSecurityPimpl::send_message - ret: %d", ret);
    return ret; //bytes written
}

int M2MConnectionSecurityPimpl::read(unsigned char* buffer, uint16_t len){
    int ret=-1;
    if(!_init_done){
        return 0;
    }

    memset( buffer, 0, len );
    do ret = mbedtls_ssl_read( &_ssl, buffer, len-1 );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    return ret; //bytes read
}

int f_send( void *ctx, const unsigned char *buf, size_t len){
    M2MConnectionHandler* handler = ((M2MConnectionHandler *) ctx);
    return handler->send_to_socket(buf, len);
}

int f_recv(void *ctx, unsigned char *buf, size_t len){
    M2MConnectionHandler* handler = ((M2MConnectionHandler *) ctx);
    return handler->receive_from_socket(buf, len);
}

int f_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t /*some*/){
    return f_recv(ctx, buf, len);
}

int entropy_poll( void *, unsigned char *output, size_t len,
                           size_t *olen )
{
    srand(time(NULL));
    char *c = (char*)malloc(len);
    memset(c, 0, len);
    for(uint16_t i=0; i < len; i++){
        c[i] = rand() % 256;
    }
    memmove(output, c, len);
    *olen = len;

    free(c);
    return( 0 );
}

void mbedtls_timing_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms ){
    tr_debug("mbedtls_timing_set_delay - intermediate: %d", int_ms);
    tr_debug("mbedtls_timing_set_delay - final: %d", fin_ms);
    M2MTimer* timer = static_cast<M2MTimer*> (data);
    if(!timer) {
        return;
    }
    if( int_ms > 0 && fin_ms > 0 ){
        tr_debug("mbedtls_timing_set_delay - start");
        cancelled = false;
        timer->stop_timer();
        timer->start_dtls_timer(int_ms, fin_ms);
    }else{
        tr_debug("mbedtls_timing_set_delay - stop");
        cancelled = true;
        timer->stop_timer();
    }
}

int mbedtls_timing_get_delay( void *data ){
    tr_debug("mbedtls_timing_get_delay");
    M2MTimer* timer = static_cast<M2MTimer*> (data);
    if(!timer){
        return 0;
    }
    if(true == cancelled) {
        tr_debug("mbedtls_timing_get_delay - ret -1");
        return -1;
    } else if( timer->is_total_interval_passed() ){
        tr_debug("mbedtls_timing_get_delay - ret 2");
        return 2;
    }else if( timer->is_intermediate_interval_passed() ){
        tr_debug("mbedtls_timing_get_delay - ret 1");
        return 1;
    }else{
        tr_debug("mbedtls_timing_get_delay - ret 0");
        return 0;
    }
}
