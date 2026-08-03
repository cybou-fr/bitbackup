// BLAKE3 — второй хеш bbk/1, наряду с SHAKE256.
//
// Разделение ролей жёсткое и намеренное: SHAKE256 выводит ключи (§4, §6),
// BLAKE3 хеширует данные и идентификаторы. В OpenSSL BLAKE3 нет, поэтому это
// отдельная зависимость (vcpkg-порт blake3).
//
// Три режима, и все три нужны формату:
//
//   обычный  content_hash файла, листья и узлы Merkle-дерева (§11, §13)
//   keyed    file_instance_id по k_instance, file_id по k_fileid (§6)
//   XOF      identity_id — 32 байта выдавливаются из потока (§4)
//
// XOF здесь не отдельный режим алгоритма, а произвольная длина вывода: у
// BLAKE3 она есть всегда, поэтому Finish принимает out_len.

#ifndef BBCORE_CRYPTO_HASH_H
#define BBCORE_CRYPTO_HASH_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace bb {

inline constexpr std::size_t kHashLen      = 32;
inline constexpr std::size_t kBlake3KeyLen = 32;

using Hash256   = std::array<std::uint8_t, kHashLen>;
using Blake3Key = std::array<std::uint8_t, kBlake3KeyLen>;

/// Место под blake3_hasher. Запас к текущим ~1.9 KiB; Hash.cpp ломает сборку,
/// если структура перерастёт его в новой версии библиотеки.
inline constexpr std::size_t kBlake3StateSize = 2048;

class Blake3 {
public:
    /// Обычный BLAKE3.
    Blake3();

    /// Keyed BLAKE3. Ключ — ровно 32 байта; в деструкторе состояние затирается.
    explicit Blake3(const Blake3Key& key);

    ~Blake3();

    Blake3(const Blake3&)            = delete;
    Blake3& operator=(const Blake3&) = delete;

    Blake3& Update(const void* data, std::size_t len);
    Blake3& Update(std::string_view label);

    /// Доменный байт-префикс Merkle-узлов: 0x00 у листа, 0x01 у внутреннего (§11).
    Blake3& UpdateU8(std::uint8_t value);

    /// Выдавливает out_len байт. Как и у Shake256, вызывается один раз: BLAKE3
    /// позволил бы дофинализировать состояние повторно, но одинаковая
    /// дисциплина у обоих хешей дешевле, чем два разных набора правил.
    bool Finish(std::uint8_t* out, std::size_t out_len);
    bool Finish(Hash256& out);

private:
    // blake3_hasher лежит здесь же, а не в куче: Merkle-дерево считает до 8192
    // листьев, и выделение под каждый было бы платой ни за что. Заголовок при
    // этом не тянет blake3.h — размер проверяется static_assert в Hash.cpp.
    alignas(16) unsigned char state_[kBlake3StateSize];

    bool failed_ = false;
};

/// content_hash и листья Merkle: BLAKE3(data, out_len).
bool Blake3Hash(const void* data, std::size_t len,
                std::uint8_t* out, std::size_t out_len);

/// file_instance_id и file_id: BLAKE3-keyed(key, data, out_len). См. §6.
bool Blake3KeyedHash(const Blake3Key& key, const void* data, std::size_t len,
                     std::uint8_t* out, std::size_t out_len);

}  // namespace bb

#endif  // BBCORE_CRYPTO_HASH_H
