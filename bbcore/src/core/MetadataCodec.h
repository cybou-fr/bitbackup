// Метаданные чанка — ARCHITECTURE.md §13.
//
// Массива чанков здесь нет: имена выводятся из K_file, длины — из split, а
// порядок — из §12. Метаданные всех чанков одной версии файла идентичны и
// различаются ровно двумя полями — self и merkle.path.
//
// content_hash лежит в КАЖДОМ чанке, а не в выделенном первом. На этом стоят
// индексация (что лежит в архиве, не скачивая данных), обнаружение изменений
// и проверка после восстановления.
//
// Раскладка открытого текста области метаданных:
//
//   u32be(payload_len)  4 байта
//   CBOR                payload_len байт
//   нули                до размерного класса 4, 8 или 16 KiB
//
// Дополнение обязательно: len_metadata лежит в открытом header, и без
// выравнивания хранилище оценивало бы по нему длину пути и число чанков —
// merkle_path растёт как ⌈log₂(n)⌉ × 32.
//
// Нулевой хвост проверяется при разборе. Он и так под AEAD, но мусор в
// дополнении был бы скрытым каналом, а отвергнуть его стоит одного прохода.

#ifndef BBCORE_CORE_METADATACODEC_H
#define BBCORE_CORE_METADATACODEC_H

#include "bbcore/bbcore.h"

#include "core/Splitter.h"
#include "crypto/Hash.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bb {

/// Потолки длин. Совпадают с буферами bb_chunk_info за вычетом завершающего
/// нуля: то, что не влезет в C ABI, незачем и принимать.
inline constexpr std::size_t kMetadataMaxNameLen = 511;
inline constexpr std::size_t kMetadataMaxPathLen = 1023;

/// ⌈log₂(8192)⌉ = 13; запас на случай иных параметров RS.
inline constexpr std::size_t kMetadataMaxPathNodes = 32;

/// 4 байта длины + CBOR обязаны уложиться в наибольший класс.
inline constexpr std::size_t kMetadataLengthPrefix = 4;

using InstanceId  = std::array<std::uint8_t, BB_INSTANCE_ID_LEN>;
using TransformId = std::array<std::uint8_t, BB_TRANSFORM_ID_LEN>;

struct ChunkMetadata {
    std::uint32_t version = BB_FORMAT_VERSION;

    InstanceId    file_instance{};
    std::string   file_name;
    std::string   file_path;
    std::uint64_t file_size = 0;
    Hash256       content_hash{};
    std::int64_t  created    = -1;
    std::int64_t  modified   = -1;
    std::uint32_t attributes = 0;

    TransformId   transform_id{};
    std::uint64_t stored_size = 0;

    SplitProfile split{};

    std::uint32_t rs_data     = 0;
    std::uint32_t rs_parity   = 0;
    std::uint32_t chunk_count = 0;

    Hash256              merkle_root{};
    std::vector<Hash256> merkle_path;

    std::uint32_t self_index    = 0;
    std::uint32_t self_stripe   = 0;
    std::uint16_t self_position = 0;
};

/// Ближайший сверху размерный класс для полезной части такой длины.
bool MetadataSizeClass(std::size_t payload_len, std::size_t* out_class);

/// Собрать открытый текст области метаданных, уже дополненный до класса.
bb_status MetadataEncode(const ChunkMetadata&       metadata,
                         std::vector<std::uint8_t>& out_plaintext);

/// Разобрать открытый текст. Вход недоверенный: длина обязана быть ровно
/// размерным классом, CBOR — канонической формой, дополнение — нулями.
bb_status MetadataDecode(const std::uint8_t* plaintext, std::size_t len,
                         ChunkMetadata&      out_metadata);

}  // namespace bb

#endif  // BBCORE_CORE_METADATACODEC_H
