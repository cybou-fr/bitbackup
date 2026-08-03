#include "util/Base32.h"

namespace bb {
namespace {

const char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

/// -1 для всех символов вне алфавита. Верхний регистр не принимается:
/// каноническая форма имени ровно одна.
int DecodeSymbol(char c)
{
    if (c >= 'a' && c <= 'z') {
        return c - 'a';
    }
    if (c >= '2' && c <= '7') {
        return c - '2' + 26;
    }
    return -1;
}

}  // namespace

bool Base32Encode(const std::uint8_t* data,
                  std::size_t         len,
                  char*               out,
                  std::size_t         cap,
                  std::size_t*        out_len)
{
    const std::size_t needed = Base32EncodedLen(len);
    if (out_len != nullptr) {
        *out_len = needed;
    }
    if (out == nullptr || cap < needed) {
        return false;
    }
    if (len != 0 && data == nullptr) {
        return false;
    }

    std::uint32_t buffer = 0;
    unsigned      bits   = 0;
    std::size_t   pos    = 0;

    for (std::size_t i = 0; i < len; ++i) {
        buffer = (buffer << 8) | static_cast<std::uint32_t>(data[i]);
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[pos++] = kAlphabet[(buffer >> bits) & 0x1Fu];
        }
    }

    if (bits > 0) {
        out[pos++] = kAlphabet[(buffer << (5 - bits)) & 0x1Fu];
    }

    return pos == needed;
}

bool Base32Decode(const char*   text,
                  std::size_t   text_len,
                  std::uint8_t* out,
                  std::size_t   cap,
                  std::size_t*  out_len)
{
    const std::size_t needed = Base32DecodedLen(text_len);
    if (out_len != nullptr) {
        *out_len = needed;
    }
    if (text == nullptr || (needed != 0 && out == nullptr) || cap < needed) {
        return false;
    }

    // 1, 3 и 6 остаточных символов не могут появиться при корректном
    // кодировании: они несут 5, 15 и 30 бит, что не даёт целого байта
    // сверх уже собранных.
    const std::size_t tail = text_len % 8;
    if (tail == 1 || tail == 3 || tail == 6) {
        return false;
    }

    std::uint32_t buffer = 0;
    unsigned      bits   = 0;
    std::size_t   pos    = 0;

    for (std::size_t i = 0; i < text_len; ++i) {
        const int value = DecodeSymbol(text[i]);
        if (value < 0) {
            return false;
        }

        buffer = (buffer << 5) | static_cast<std::uint32_t>(value);
        bits += 5;

        if (bits >= 8) {
            bits -= 8;
            if (pos >= needed) {
                return false;
            }
            out[pos++] = static_cast<std::uint8_t>((buffer >> bits) & 0xFFu);
        }
    }

    // Остаточные биты последнего символа обязаны быть нулевыми, иначе
    // у одних и тех же байт было бы несколько допустимых написаний.
    if (bits > 0 && (buffer & ((1u << bits) - 1u)) != 0) {
        return false;
    }

    return pos == needed;
}

}  // namespace bb
