
#ifndef __M2M_CONNECTION_SECURITY_PIMPL_H__
#define __M2M_CONNECTION_SECURITY_PIMPL_H__

#include "lwm2m-client/m2mconnectionsecurity.h"
#include "lwm2m-client/m2mtimerobserver.h"

#include "mbedtls/config.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/entropy_poll.h"

class M2MSecurity;
class M2MTimer;

//TODO: Should we let application to select these or not??
const static int PSK_SUITES[] = {
    MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8,
    MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8,
    0
};


class M2MConnectionSecurityPimpl : public M2MTimerObserver {
private:
    // Prevents the use of assignment operator by accident.
    M2MConnectionSecurityPimpl& operator=( const M2MConnectionSecurityPimpl& /*other*/ );
    // Prevents the use of copy constructor by accident
    M2MConnectionSecurityPimpl( const M2MConnectionSecurityPimpl& /*other*/ );

public:
    M2MConnectionSecurityPimpl();

    virtual ~M2MConnectionSecurityPimpl();

    void reset();

    int init(const M2MSecurity *security);

    int start_connecting_non_blocking(M2MConnectionHandler* connHandler);
    int continue_connecting();

    int connect(M2MConnectionHandler* connHandler);

    int send_message(unsigned char *message, int len);

    int read(unsigned char* buffer, uint16_t len);

public: //From M2MTimerObserver
    virtual void timer_expired(M2MTimerObserver::Type type);

private:
    bool                        _init_done;
    mbedtls_ssl_config          _conf;
    mbedtls_ssl_context         _ssl;

    mbedtls_x509_crt            _cacert;
    mbedtls_x509_crt            _owncert;
    mbedtls_pk_context          _pkey;

    mbedtls_ctr_drbg_context    _ctr_drbg;
    uint32_t                    _flags;
    M2MTimer                    *_timmer;

    unsigned char               _buf[1024];

    friend class Test_M2MConnectionSecurityPimpl;
};

#endif //__M2M_CONNECTION_SECURITY_PIMPL_H__
