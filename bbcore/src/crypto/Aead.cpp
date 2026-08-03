#include "crypto/Aead.h"

#include "bbcore/bbcore.h"

#include <openssl/evp.h>

#include <limits>

namespace bb {
namespace {

constexpr char kCipherName[] = "AES-256-GCM-SIV";

/// Шифр берётся из провайдера один раз на процесс: EVP_CIPHER_fetch по имени
/// заметно дороже самого шифрования коротких метаданных, а чанков бывает 8192.
/// Объект живёт до конца процесса намеренно — освобождать его в деструкторе
/// статика значило бы гонку с потоками, которые ещё шифруют.
const EVP_CIPHER* Cipher()
{
    static const EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, kCipherName, nullptr);
    return cipher;
}

/// OpenSSL меряет длины int'ом. Формат до таких размеров не доходит — фрагмент
/// ограничен split-профилем, — но проверка стоит одного сравнения.
bool FitsInInt(std::size_t len)
{
    return len <= static_cast<std::size_t>(std::numeric_limits<int>::max());
}

struct CtxGuard {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // Объявленный копирующий конструктор — тоже конструктор, поэтому
    // конструктор по умолчанию приходится вернуть явно.
    CtxGuard() = default;

    ~CtxGuard()
    {
        if (ctx != nullptr) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }

    CtxGuard(const CtxGuard&)            = delete;
    CtxGuard& operator=(const CtxGuard&) = delete;
};

bool UpdateAad(EVP_CIPHER_CTX* ctx, const void* aad, std::size_t aad_len, bool encrypt)
{
    if (aad_len == 0) {
        return true;
    }
    if (aad == nullptr) {
        return false;
    }

    int written = 0;
    const unsigned char* bytes = static_cast<const unsigned char*>(aad);

    return encrypt
        ? EVP_EncryptUpdate(ctx, nullptr, &written, bytes, static_cast<int>(aad_len)) == 1
        : EVP_DecryptUpdate(ctx, nullptr, &written, bytes, static_cast<int>(aad_len)) == 1;
}

}  // namespace

bool AeadIsAvailable()
{
    return Cipher() != nullptr;
}

bool AeadSeal(const AeadKey&   key,
              const AeadNonce& nonce,
              const void*      aad, std::size_t aad_len,
              const void*      plaintext, std::size_t plain_len,
              std::uint8_t*    out, std::size_t out_cap, std::size_t* out_len)
{
    const std::size_t needed = AeadSealedLen(plain_len);
    if (out_len != nullptr) {
        *out_len = needed;
    }

    if (out == nullptr || out_cap < needed) {
        return false;
    }
    if (plaintext == nullptr && plain_len != 0) {
        return false;
    }
    if (!FitsInInt(plain_len) || !FitsInInt(aad_len)) {
        return false;
    }

    const EVP_CIPHER* cipher = Cipher();
    CtxGuard          guard;
    if (cipher == nullptr || guard.ctx == nullptr) {
        return false;
    }

    if (EVP_EncryptInit_ex2(guard.ctx, cipher, key.data(), nonce.data(), nullptr) != 1) {
        return false;
    }
    if (!UpdateAad(guard.ctx, aad, aad_len, true)) {
        return false;
    }

    // Update вызывается всегда, даже на пустом открытом тексте: реализация
    // GCM-SIV в OpenSSL считает шифрование без него незавершённым и отказывает
    // в Final. Пустое сообщение — законный случай, оно даёт один тег.
    const std::uint8_t  empty = 0;
    const std::uint8_t* input =
        plain_len != 0 ? static_cast<const std::uint8_t*>(plaintext) : &empty;

    int written = 0;
    if (EVP_EncryptUpdate(guard.ctx, out, &written, input,
                          static_cast<int>(plain_len)) != 1) {
        return false;
    }

    int final_written = 0;
    if (EVP_EncryptFinal_ex(guard.ctx, out + written, &final_written) != 1) {
        return false;
    }

    const std::size_t cipher_len =
        static_cast<std::size_t>(written) + static_cast<std::size_t>(final_written);
    if (cipher_len != plain_len) {
        return false;  // потоковый шифр обязан сохранять длину
    }

    return EVP_CIPHER_CTX_ctrl(guard.ctx, EVP_CTRL_AEAD_GET_TAG,
                               static_cast<int>(kAeadTagLen), out + cipher_len) == 1;
}

bool AeadOpen(const AeadKey&      key,
              const AeadNonce&    nonce,
              const void*         aad, std::size_t aad_len,
              const std::uint8_t* sealed, std::size_t sealed_len,
              std::uint8_t*       out, std::size_t out_cap, std::size_t* out_len)
{
    if (sealed == nullptr || sealed_len < kAeadTagLen) {
        if (out_len != nullptr) {
            *out_len = 0;
        }
        return false;
    }

    const std::size_t plain_len = sealed_len - kAeadTagLen;
    if (out_len != nullptr) {
        *out_len = plain_len;
    }

    // Пустое сообщение — это один тег, и выходного буфера для него не нужно:
    // из vector нулевой длины data() вернёт nullptr, а проверить тег всё равно
    // обязаны. Требование ненулевого out действует только когда есть что писать.
    if ((out == nullptr && plain_len != 0) || out_cap < plain_len) {
        return false;
    }
    if (!FitsInInt(plain_len) || !FitsInInt(aad_len)) {
        return false;
    }

    const EVP_CIPHER* cipher = Cipher();
    CtxGuard          guard;
    if (cipher == nullptr || guard.ctx == nullptr) {
        return false;
    }

    if (EVP_DecryptInit_ex2(guard.ctx, cipher, key.data(), nonce.data(), nullptr) != 1) {
        return false;
    }

    // Тег выставляется до данных, а не перед Final: в GCM-SIV он участвует в
    // выводе счётчика, поэтому без него расшифровать нечего.
    if (EVP_CIPHER_CTX_ctrl(guard.ctx, EVP_CTRL_AEAD_SET_TAG,
                            static_cast<int>(kAeadTagLen),
                            const_cast<std::uint8_t*>(sealed + plain_len)) != 1) {
        return false;
    }

    if (!UpdateAad(guard.ctx, aad, aad_len, false)) {
        return false;
    }

    // Симметрично шифрованию: Update обязателен и для пустого сообщения.
    std::uint8_t  scratch = 0;
    std::uint8_t* target  = out != nullptr ? out : &scratch;

    int written = 0;
    if (EVP_DecryptUpdate(guard.ctx, target, &written, sealed,
                          static_cast<int>(plain_len)) != 1) {
        bb_secure_zero(out, plain_len);
        return false;
    }

    int final_written = 0;
    if (EVP_DecryptFinal_ex(guard.ctx, target + written, &final_written) != 1) {
        // Тег не сошёлся. Открытый текст уже мог быть записан в out, и отдавать
        // его наружу нельзя ни при каких условиях: неаутентифицированные данные
        // это ровно то, от чего защищает AEAD.
        bb_secure_zero(out, plain_len);
        return false;
    }

    const std::size_t produced =
        static_cast<std::size_t>(written) + static_cast<std::size_t>(final_written);
    if (produced != plain_len) {
        bb_secure_zero(out, plain_len);
        return false;
    }

    return true;
}

}  // namespace bb
