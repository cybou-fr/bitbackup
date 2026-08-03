// base32 lowercase без padding, RFC 4648, алфавит "abcdefghijklmnopqrstuvwxyz234567".
//
// Выбран вместо hex и base64 потому, что имена объектов должны оставаться
// уникальными при приведении регистра (Windows, FAT32, часть FTP-серверов)
// и быть безопасными в URL и путях. См. docs/ARCHITECTURE.md §5.

#ifndef BBCORE_UTIL_BASE32_H
#define BBCORE_UTIL_BASE32_H

#include <cstddef>
#include <cstdint>

namespace bb {

/// Длина закодированного представления len байт, без завершающего нуля.
constexpr std::size_t Base32EncodedLen(std::size_t len)
{
    return (len * 8 + 4) / 5;
}

/// Максимальное число байт, которое может дать декодирование len символов.
constexpr std::size_t Base32DecodedLen(std::size_t len)
{
    return len * 5 / 8;
}

/// Кодирует data в out. Завершающий ноль не пишется.
/// Возвращает false, если cap меньше Base32EncodedLen(len).
bool Base32Encode(const std::uint8_t* data,
                  std::size_t         len,
                  char*               out,
                  std::size_t         cap,
                  std::size_t*        out_len);

/// Декодирует ровно text_len символов.
///
/// Строгий разбор: посторонние символы, padding '=' и ненулевые остаточные
/// биты отвергаются. Это важно, потому что имя объекта участвует в AAD —
/// два разных написания одного имени не должны существовать.
bool Base32Decode(const char*    text,
                  std::size_t    text_len,
                  std::uint8_t*  out,
                  std::size_t    cap,
                  std::size_t*   out_len);

}  // namespace bb

#endif  // BBCORE_UTIL_BASE32_H
