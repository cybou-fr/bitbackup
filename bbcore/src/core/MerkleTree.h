// Merkle-дерево над shard cores — ARCHITECTURE.md §11.
//
// Зачем оно, если у data shards есть AEAD-тег: у parity shards тега нет, они
// результат Reed–Solomon, а не шифрования. Испорченный parity без дерева молча
// превратил бы восстановление в мусор, и виновника пришлось бы искать
// перебором подмножеств шардов.
//
//   leaf_i   = BLAKE3(0x00 || shard_core_i, 32)
//   internal = BLAKE3(0x01 || left || right, 32)
//
// Нечётный узел на уровне поднимается наверх без изменений.
//
// Доменные байты обязательны: без них лист длиной 64 байта был бы неотличим от
// внутреннего узла, и подделать поддерево стало бы возможно.
//
// Корень берётся из первого успешно расшифрованного чанка, и все последующие
// проверяются своим путём против ЭТОГО корня. Чанк с самосогласованным
// собственным корнем отвергается.

#ifndef BBCORE_CORE_MERKLETREE_H
#define BBCORE_CORE_MERKLETREE_H

#include "crypto/Hash.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bb {

/// Лист: BLAKE3(0x00 || shard_core).
bool MerkleLeaf(const void* shard_core, std::size_t len, Hash256& out_leaf);

/// Внутренний узел: BLAKE3(0x01 || left || right).
bool MerkleNode(const Hash256& left, const Hash256& right, Hash256& out_node);

/// Корень по готовым листьям. Пустой список — ошибка: файл без единого шарда
/// не существует, даже пустой даёт один чанк.
bool MerkleRoot(const std::vector<Hash256>& leaves, Hash256& out_root);

/// Путь для листа с индексом index: соседи снизу вверх.
///
/// Длина пути — ⌈log2(n)⌉ и меньше, если по дороге встретился одиночный узел,
/// поднятый наверх без пары. Поэтому размер пути у разных листьев одного
/// дерева может отличаться, и метаданные обязаны хранить его целиком, а не
/// вычислять из числа чанков.
bool MerklePath(const std::vector<Hash256>& leaves, std::size_t index,
                std::vector<Hash256>& out_path);

/// Проверка листа путём против корня.
///
/// index нужен, чтобы знать, с какой стороны подставлять соседа: перепутанная
/// сторона дала бы другой корень, и подделка прошла бы только при симметричной
/// хеш-функции, каковой BLAKE3 не является.
bool MerkleVerify(const Hash256& leaf, std::size_t index, std::size_t leaf_count,
                  const std::vector<Hash256>& path, const Hash256& root);

}  // namespace bb

#endif  // BBCORE_CORE_MERKLETREE_H
