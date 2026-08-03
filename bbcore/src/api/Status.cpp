#include "bbcore/bbcore.h"

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
    // Пока инициализировать нечего. Здесь появится настройка OpenSSL
    // provider'ов, liboqs и проверка доступности AES-NI.
    return BB_OK;
}
