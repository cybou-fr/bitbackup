// Всё, что выводится из K_file. Собрано в одном месте намеренно: это те самые
// деривации, из-за которых порядок операций в §10 обязателен, и держать их
// разбросанными по модулям — приглашение вывести ключ шарда до того, как ему
// назначена позиция.
//
//   имя объекта (§5)
//     object_name_i = SHAKE256(K_file || u32be(i) || "bbk/1/name", 32)
//
//   шифрование фрагмента (§9)
//     K_shard = SHAKE256(K_file || u32be(stripe) || u16be(position)
//                                || "bbk/1/data",  32)
//     N_shard = SHAKE256(K_file || u32be(stripe) || u16be(position)
//                                || "bbk/1/nonce", 12)
//
//   шифрование метаданных (§14)
//     K_meta = SHAKE256(K_file || u32be(i) || "bbk/1/metadata",  32)
//     N_meta = SHAKE256(K_file || u32be(i) || "bbk/1/metanonce", 12)
//
//   сам ключ файла (§6)
//     K_file = SHAKE256(k_filekey || file_id || "bbk/1/filekey", 32)
//
// Ключ и нонс здесь выводятся ДВУМЯ разными вызовами SHAKE с разными метками,
// а не одной выжимкой на 44 байта, как у envelope: так записано в §9 и §14, и
// эти формулы в спецификации есть — в отличие от нонса §15, которого не было.

#ifndef BBCORE_CORE_KEYSCHEDULE_H
#define BBCORE_CORE_KEYSCHEDULE_H

#include "crypto/Aead.h"
#include "crypto/Hash.h"
#include "crypto/HybridKem.h"

#include <cstdint>

namespace bb {

/// Сырое 32-байтовое имя объекта; в текст его переводит bb_object_name_format.
using ObjectName = std::array<std::uint8_t, BB_NAME_LEN>;

/// K_file = SHAKE256(k_filekey || file_id || "bbk/1/filekey", 32). См. §6.
///
/// k_filekey берётся из identity (§4). Тип у него тот же самый: Hash256,
/// FileKey, AeadKey и IdentityKey — все псевдонимы std::array<uint8_t, 32>,
/// и различаются только по смыслу в сигнатурах.
bool DeriveFileKey(const Hash256& k_filekey,
                   const Hash256& file_id,
                   FileKey&       out_k_file);

/// Имя объекта по каноническому индексу §12.
bool DeriveObjectName(const FileKey& k_file, std::uint32_t index,
                      ObjectName& out_name);

/// Ключ и нонс фрагмента. Позиция — 0..(rs_data + rs_parity - 1), то есть
/// parity shards тоже имеют её, хотя сами AEAD не используют.
bool DeriveShardKey(const FileKey& k_file,
                    std::uint32_t  stripe,
                    std::uint16_t  position,
                    AeadKey&       out_key,
                    AeadNonce&     out_nonce);

/// Ключ и нонс метаданных чанка по каноническому индексу §12.
bool DeriveMetadataKey(const FileKey& k_file, std::uint32_t index,
                       AeadKey& out_key, AeadNonce& out_nonce);

}  // namespace bb

#endif  // BBCORE_CORE_KEYSCHEDULE_H
