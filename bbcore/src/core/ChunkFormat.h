// Контейнер .bbk — ARCHITECTURE.md §16.
//
// Открытого заголовка нет: в объекте нет ни одного байта открытого текста.
//
//   0                  ct_mlkem      1568   неотличим от случайного
//   1568               epk_x25519      32   неотличим от случайного
//   1600               wrapped         80   AEAD ciphertext
//   1680               enc_metadata  class + 16
//   1680 + class + 16  shard_core    остаток минус padding
//
// Зашифровать нельзя только ct_mlkem и epk_x25519 — это вход декапсуляции,
// то, из чего получается первый ключ. Но и они не выдают ничего: ciphertext
// ML-KEM и точка X25519 неотличимы от равномерного шума.
//
// Границы читатель находит пробным расшифрованием: класс метаданных 4, 8 или
// 16 KiB, успешный AEAD-тег и есть подтверждение выбора. Длина padding лежит
// внутри метаданных, длина shard core получается вычитанием из размера объекта.
//
// suite_id тоже отсутствует. Он входит в transcript combiner'а (§15), поэтому
// неверный suite не даст вскрыть wrapped. Плата: чанк чужого suite неотличим
// от повреждённого — и то, и другое BB_ERR_DECRYPT_FAILED.
//
// Принадлежность identity проверяется по имени объекта, которое несёт
// identity_id (§5), поэтому BB_ERR_WRONG_IDENTITY сохраняется.

#ifndef BBCORE_CORE_CHUNKFORMAT_H
#define BBCORE_CORE_CHUNKFORMAT_H

#include "bbcore/bbcore.h"

#include "core/KeySchedule.h"
#include "core/MetadataCodec.h"
#include "crypto/HybridKem.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bb {

/// ct_mlkem + epk_x25519 + wrapped.
inline constexpr std::size_t kChunkPrefixLen =
    kMlKemCiphertextLen + kX25519KeyLen + kEnvelopeWrappedLen;

static_assert(kChunkPrefixLen == 1680, "chunk prefix must match §16");

/// Наименьший осмысленный объект: префикс плюс метаданные младшего класса.
inline constexpr std::size_t kChunkMinLen =
    kChunkPrefixLen + BB_META_CLASS_MIN + BB_TAG_LEN;

struct ChunkBuildInput {
    /// Получатель. Приватные ключи не нужны — чанк можно адресовать чужой
    /// identity, открытой из публичного блоба (§26).
    const MlKemKeyPair*  recipient_kem       = nullptr;
    const X25519KeyPair* recipient_classic   = nullptr;
    const Hash256*       recipient_identity  = nullptr;

    std::uint16_t suite_id = BB_SUITE_ID;

    const FileKey* k_file  = nullptr;
    const Hash256* file_id = nullptr;

    /// Имя этого чанка, выведенное из K_file и канонического индекса (§5).
    /// Входит в AAD метаданных, поэтому чанк нельзя переставить под чужим
    /// именем.
    const ObjectName* object_name = nullptr;

    const ChunkMetadata* metadata = nullptr;

    const std::uint8_t* shard_core     = nullptr;
    std::size_t         shard_core_len = 0;
};

/// Собрать объект целиком. Длина дополнения берётся из metadata->padding;
/// байты дополнения — случайные, как и требует §16.
bb_status ChunkBuild(const ChunkBuildInput& input, std::vector<std::uint8_t>& out);

struct ChunkOpened {
    ChunkMetadata metadata;

    FileKey k_file{};
    Hash256 file_id{};

    /// Смещение и длина shard core внутри объекта.
    std::size_t core_offset = 0;
    std::size_t core_length = 0;

    /// Класс метаданных, который подошёл.
    std::size_t metadata_class = 0;

    std::uint16_t suite_id = 0;
};

/// Вскрыть чанк своими приватными ключами.
///
/// blob можно передать усечённым до префикса и области метаданных — так и
/// работает range-чтение (§16). Тогда core_length считается по object_size,
/// который передаётся отдельно; если он равен blob_len, длина ядра выводится
/// из самого blob.
///
///   BB_ERR_BAD_CONTAINER    объект короче осмысленного минимума
///   BB_ERR_WRONG_IDENTITY   имя объекта адресовано не нам
///   BB_ERR_DECRYPT_FAILED   не подошёл ни один класс метаданных
///
/// object_name обязателен: он входит в AAD метаданных, и без него чанк не
/// вскрыть. У вызывающего он есть всегда — это имя, под которым объект лежит
/// в хранилище.
///
/// КАК НАХОДИТСЯ КАНОНИЧЕСКИЙ ИНДЕКС. K_meta зависит от индекса чанка (§14), а
/// индекс лежит внутри тех самых метаданных. Круг разрывается именем: оно тоже
/// выведено из K_file и индекса (§5), поэтому после вскрытия envelope читатель
/// перебирает i, пока name(i) не совпадёт с именем объекта. Это ровно то, ради
/// чего имена выводятся, а не хешируются от содержимого. Перебор ограничен
/// BB_MAX_CHUNKS и стоит одной выжимки SHAKE на шаг.
///
/// Побочный эффект полезен: имя обязано быть выводимо из K_file, то есть объект
/// нельзя подставить под чужим именем.
///
/// name_identity — часть идентификатора из полного имени `<id>.<name>.bbk`.
bb_status ChunkOpen(const MlKemKeyPair&  self_kem,
                    const X25519KeyPair& self_classic,
                    const Hash256&       self_identity,
                    const Hash256&       name_identity,
                    const ObjectName&    object_name,
                    const std::uint8_t*  blob,
                    std::size_t          blob_len,
                    std::uint64_t        object_size,
                    ChunkOpened&         out);

/// Имена всех объектов файла по расшифрованным метаданным (§5, §12).
///
/// Ровно та операция, ради которой имена выводятся, а не хешируются: один
/// вскрытый чанк даёт адреса всех остальных.
bb_status ChunkObjectNames(const FileKey&           k_file,
                           const ChunkMetadata&     metadata,
                           std::vector<ObjectName>& out_names);

}  // namespace bb

#endif  // BBCORE_CORE_CHUNKFORMAT_H
