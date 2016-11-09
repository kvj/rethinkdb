// Copyright 2010-2016 RethinkDB, all rights reserved.
#include "crypto/hmac.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>

#include "crypto/error.hpp"

namespace crypto {

class hmac_ctx_wrapper_t {
public:
    hmac_ctx_wrapper_t() {
        HMAC_CTX_init(&m_hmac_ctx);
    }

    ~hmac_ctx_wrapper_t() {
        HMAC_CTX_cleanup(&m_hmac_ctx);
    }

    HMAC_CTX *get() {
        return &m_hmac_ctx;
    }

private:
    HMAC_CTX m_hmac_ctx;
};

std::array<unsigned char, SHA256_DIGEST_LENGTH> detail::hmac_sha256(
        unsigned char const *key,
        size_t key_size,
        unsigned char const *data,
        size_t data_size) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> hmac;

    hmac_ctx_wrapper_t hmac_ctx;
    if (HMAC_Init_ex(hmac_ctx.get(), key, key_size, EVP_sha256(), nullptr) != 1) {
        throw openssl_error_t(ERR_get_error());
    }
    if (HMAC_Update(hmac_ctx.get(), data, data_size) != 1) {
        throw openssl_error_t(ERR_get_error());
    }
    if (HMAC_Final(hmac_ctx.get(), hmac.data(), nullptr) != 1) {
        throw openssl_error_t(ERR_get_error());
    }

    return hmac;
}

}  // namespace crypto
