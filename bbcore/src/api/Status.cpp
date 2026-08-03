#include "bbcore/bbcore.h"

#include "crypto/Aead.h"

#include <openssl/evp.h>

namespace {

bool PkeyAlgorithmIsAvailable(const char* name)
{
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(nullptr, name, nullptr);
    if (context == nullptr) {
        return false;
    }
    EVP_PKEY_CTX_free(context);
    return true;
}

}  // namespace

BB_API const char* BB_CALL bb_status_text(bb_status status)
{
    switch (status) {
        case BB_OK:                   return "ok";
        case BB_ERR_INVALID_ARG:      return "invalid argument";
        case BB_ERR_BUFFER_TOO_SMALL: return "buffer too small";
        case BB_ERR_OUT_OF_MEMORY:    return "out of memory";
        case BB_ERR_UNSUPPORTED:      return "unsupported format or crypto suite";
        case BB_ERR_BAD_MNEMONIC:     return "invalid BIP39 mnemonic";
        case BB_ERR_BAD_CONTAINER:    return "malformed .bbk container";
        case BB_ERR_DECRYPT_FAILED:   return "decryption failed: authentication tag mismatch";
        case BB_ERR_WRONG_IDENTITY:   return "chunk is addressed to a different identity";
        case BB_ERR_INTEGRITY:        return "integrity check failed";
        case BB_ERR_UNRECOVERABLE:    return "too many shards lost to reconstruct";
        case BB_ERR_STORAGE:          return "storage backend error";
        case BB_ERR_IO:               return "i/o error";
        case BB_ERR_CANCELLED:        return "cancelled";
        case BB_ERR_INTERNAL:         return "internal error";
    }
    return "unknown status";
}

BB_API const char* BB_CALL bb_version(void)
{
    return "bbcore 0.1.0 (bbk/1)";
}

BB_API bb_status BB_CALL bb_init(void)
{
    // Проверяем активные provider'ы в рантайме: компилируемость OpenSSL API
    // сама по себе не гарантирует доступность нужных алгоритмов в процессе.
    if (!PkeyAlgorithmIsAvailable("ML-KEM-1024")
     || !PkeyAlgorithmIsAvailable("X25519")
     || !bb::AeadIsAvailable()) {
        return BB_ERR_UNSUPPORTED;
    }

    return BB_OK;
}
